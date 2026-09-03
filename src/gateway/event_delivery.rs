// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Gateway event delivery, WAL persistence, and background forwarding.
//!
//! # WAL delivery API
//!
//! Production emission uses the durable WAL persist seams only:
//! [`EventSink::persist_durable_event`], [`EventSink::persist_admitted_decision`],
//! [`EventSink::persist_spend`], [`EventSink::persist_ai_usage`], and
//! [`EventSink::persist_trail`]. Start the background worker with
//! [`spawn_wal_delivery_worker`] and coordinate shutdown with
//! [`drain_forwarding_tasks_on_shutdown`].
//!
//! # Durable envelopes
//!
//! Every decision, spend, AI-usage, and Trail side-effect is wrapped in a
//! [`DurableEventEnvelope`] and `fsync`d to the WAL **before** upstream API
//! delivery (and before provider dispatch for admitted decisions via
//! [`EventSink::persist_admitted_decision`]).
//!
//! # WAL delivery worker
//!
//! [`spawn_wal_delivery_worker`] drains the WAL with bounded exponential
//! backoff + jitter, a per-attempt deadline, acknowledgement only after an API
//! 2xx that echoes the matching `delivery_id`, replay on network/408/429/5xx,
//! and AES-256-GCM encrypted quarantine for other 4xx responses. Quarantine
//! retains the WAL record bytes and keeps [`quarantine_blocks_readiness`] true
//! until an operator acknowledges and corrects the quarantine document.
//! [`snapshot_audit_wal_delivery`] exports WAL delivery counters.

use super::*;
use crate::gateway::{event_wal, metrics, usage_authorization, usage_authorization_pipeline};
use crate::retry::{compute_delay, RetryPolicy};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering as AtomicOrdering};

/// The durable side-effect categories accepted by the gateway event WAL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableEventKind {
    Decision,
    Spend,
    AiUsage,
    Trail,
    /// Immutable usage-authorization completion record.
    UaComplete,
}

impl DurableEventKind {
    /// Stable wire/storage label for this durable event category.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::Spend => "spend",
            Self::AiUsage => "ai_usage",
            Self::Trail => "trail",
            Self::UaComplete => "ua_complete",
        }
    }

    /// True when this kind is a usage-authorization completion record.
    fn is_usage_authorization_completion(self) -> bool {
        matches!(self, Self::UaComplete)
    }
}

/// Stable, digest-bound unit written to the gateway WAL before delivery.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DurableEventEnvelope {
    pub delivery_id: String,
    pub event_id: String,
    pub event_kind: DurableEventKind,
    pub org_id: Option<String>,
    pub team_id: Option<String>,
    pub request_id: String,
    pub created_at: String,
    pub payload_sha256: String,
    pub payload: serde_json::Value,
}

impl DurableEventEnvelope {
    /// Build an envelope whose digest covers the exact serialized payload.
    pub fn new(
        event_kind: DurableEventKind,
        request_id: &str,
        payload: serde_json::Value,
    ) -> Result<Self, DurableEventError> {
        let request_id = required_text(request_id, "request_id")?;
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|error| DurableEventError::Serialization(error.to_string()))?;
        let payload_sha256 = hex::encode(Sha256::digest(&payload_bytes));
        let event_id = payload_text(
            &payload,
            &[
                "/event_id",
                "/record_id",
                "/id",
                "/trail_event_id",
                "/metadata/event_id",
            ],
        )
        .unwrap_or_else(|| format!("{}:{request_id}", event_kind.as_str()));
        let org_id = payload_text(
            &payload,
            &["/org_id", "/identity_context/org_id", "/metadata/org_id"],
        );
        let team_id = payload_text(
            &payload,
            &["/team_id", "/identity_context/team_id", "/metadata/team_id"],
        );
        let created_at = payload_text(
            &payload,
            &["/created_at", "/captured_at", "/timestamp", "/event_time"],
        )
        .unwrap_or_else(|| Utc::now().to_rfc3339());

        Ok(Self {
            delivery_id: uuid::Uuid::new_v4().to_string(),
            event_id,
            event_kind,
            org_id,
            team_id,
            request_id,
            created_at,
            payload_sha256,
            payload,
        })
    }
}

/// Failure to construct or fsync a durable event envelope.
#[derive(Debug, thiserror::Error)]
pub enum DurableEventError {
    #[error("{0} must not be empty")]
    InvalidField(&'static str),
    #[error("durable event serialization failed: {0}")]
    Serialization(String),
    #[error("durable event WAL lock failed")]
    WalLock,
    #[error("durable event WAL write failed: {0}")]
    WalWrite(String),
}

/// Inline UA financial WAL delivery failure surfaced to request settlement paths.
#[derive(Debug, thiserror::Error)]
pub enum UaFinancialWalError {
    #[error("UA financial WAL persist failed: {0}")]
    Persist(DurableEventError),
    #[error("UA financial WAL delivery failed: {0}")]
    Delivery(String),
}

fn ua_authorization_id_from_payload(payload: &serde_json::Value) -> Option<String> {
    payload
        .get("gateway_usage_authorization_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn ua_complete_request_from_payload(payload: &serde_json::Value) -> Option<serde_json::Value> {
    payload.get("complete_request").cloned()
}

#[derive(Debug)]
enum DeliveryDisposition {
    Accepted,
    Retry { reason: String },
    Permanent { status: u16, body: String },
}

/// Public snapshot of WAL / delivery / quarantine state for readiness + metrics
///.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditWalDeliverySnapshot {
    /// Approximate unacknowledged WAL records (`records_written - ack_count`).
    pub wal_records: u64,
    /// Current on-disk WAL byte total.
    pub wal_bytes: u64,
    /// Age in seconds of the oldest unacked WAL record, when one exists.
    pub oldest_age_seconds: Option<u64>,
    /// Cumulative delivery retries since process start.
    pub delivery_retries_total: u64,
    /// Cumulative permanent-quarantine writes since process start.
    pub delivery_quarantine_total: u64,
    /// Unix timestamp of the last successful delivery acknowledgement.
    pub delivery_last_success_unix: Option<i64>,
    /// Current durable permanent-quarantine documents on disk.
    pub quarantine_pending: u64,
    /// True when quarantine documents remain until operator correction.
    pub readiness_blocked_by_quarantine: bool,
}

static DELIVERY_RETRIES_TOTAL: AtomicU64 = AtomicU64::new(0);
static DELIVERY_QUARANTINE_TOTAL: AtomicU64 = AtomicU64::new(0);
static DELIVERY_LAST_SUCCESS_UNIX: AtomicI64 = AtomicI64::new(0);

fn wal_delivery_retry_policy() -> RetryPolicy {
    RetryPolicy {
        // WAL delivery retries indefinitely; only the delay is bounded.
        max_retries: u32::MAX,
        base_delay: Duration::from_millis(100),
        multiplier: 2.0,
        max_delay: Duration::from_secs(5),
        jitter: 0.25,
    }
}

fn classify_http_delivery_status(status: reqwest::StatusCode) -> DeliveryDisposition {
    let code = status.as_u16();
    if status.is_success() {
        // Caller must still verify matching delivery_id before accepting.
        return DeliveryDisposition::Accepted;
    }
    if code == 408 || code == 429 || (status.is_server_error() && code != 507) {
        return DeliveryDisposition::Retry {
            reason: format!("HTTP {code}"),
        };
    }
    DeliveryDisposition::Permanent {
        status: code,
        body: String::new(),
    }
}

fn extract_ack_delivery_id(body: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(body).ok()?;
    value
        .get("delivery_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(ToOwned::to_owned)
}

fn quarantine_key_from_token(api_token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"verdictan-event-wal-quarantine-v1\0");
    hasher.update(api_token.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn encrypt_quarantine_payload(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(String, String), std::io::Error> {
    use aes_gcm::{
        aead::{Aead, AeadCore, OsRng},
        Aes256Gcm, KeyInit,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("quarantine cipher init failed: {error}"),
        )
    })?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|error| std::io::Error::other(format!("quarantine encrypt failed: {error}")))?;
    Ok((STANDARD.encode(nonce), STANDARD.encode(ciphertext)))
}

fn decrypt_quarantine_payload(
    key: &[u8; 32],
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> Result<Vec<u8>, std::io::Error> {
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let nonce_bytes = STANDARD.decode(nonce_b64).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("quarantine nonce decode failed: {error}"),
        )
    })?;
    if nonce_bytes.len() != 12 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "quarantine nonce must be 12 bytes, got {}",
                nonce_bytes.len()
            ),
        ));
    }
    let ciphertext = STANDARD.decode(ciphertext_b64).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("quarantine ciphertext decode failed: {error}"),
        )
    })?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("quarantine cipher init failed: {error}"),
        )
    })?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|error| std::io::Error::other(format!("quarantine decrypt failed: {error}")))
}

fn permanent_quarantine_dir(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("event-retry").join("quarantine")
}

fn count_permanent_quarantine_documents(quarantine_dir: &std::path::Path) -> u64 {
    std::fs::read_dir(quarantine_dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("permanent-") && name.ends_with(".json"))
        })
        .count() as u64
}

/// True when durable permanent-quarantine documents remain on disk.
///
// readiness must fail closed while this returns true.
pub fn quarantine_blocks_readiness() -> bool {
    let data_dir = std::env::var("VERDICTAN_DATA_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("verdictan"));
    count_permanent_quarantine_documents(&permanent_quarantine_dir(&data_dir)) > 0
}

/// Mark a permanent quarantine document as operator-acknowledged/corrected by
/// removing it. Readiness remains blocked until every permanent document is gone.
fn acknowledge_corrected_quarantine(segment: u64, offset: u64) -> Result<bool, std::io::Error> {
    let data_dir = std::env::var("VERDICTAN_DATA_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("verdictan"));
    let path = permanent_quarantine_dir(&data_dir).join(format!(
        "permanent-segment-{:010}-offset-{:020}.json",
        segment, offset
    ));
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(path)?;
    Ok(true)
}

/// Snapshot WAL/delivery/quarantine stats for metrics and readiness.
pub fn snapshot_audit_wal_delivery() -> Result<AuditWalDeliverySnapshot, std::io::Error> {
    let data_dir = std::env::var("VERDICTAN_DATA_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("verdictan"));
    let quarantine_pending =
        count_permanent_quarantine_documents(&permanent_quarantine_dir(&data_dir));
    let last_success = DELIVERY_LAST_SUCCESS_UNIX.load(AtomicOrdering::Relaxed);
    let mut snapshot = AuditWalDeliverySnapshot {
        wal_records: 0,
        wal_bytes: 0,
        oldest_age_seconds: None,
        delivery_retries_total: DELIVERY_RETRIES_TOTAL.load(AtomicOrdering::Relaxed),
        delivery_quarantine_total: DELIVERY_QUARANTINE_TOTAL.load(AtomicOrdering::Relaxed),
        delivery_last_success_unix: (last_success > 0).then_some(last_success),
        quarantine_pending,
        readiness_blocked_by_quarantine: quarantine_pending > 0,
    };

    let Ok(runtime) = shared_wal_runtime() else {
        return Ok(snapshot);
    };
    let writer = runtime
        .writer
        .lock()
        .map_err(|_| std::io::Error::other("durable event WAL lock failed"))?;
    let checkpoint = writer.checkpoint()?;
    let written = writer.records_written();
    snapshot.wal_records = written.saturating_sub(checkpoint.acknowledged_count);
    snapshot.wal_bytes = writer.total_bytes();
    if let Some(event_wal::PendingItem::Record(item)) = writer.next_pending(&checkpoint)? {
        if let Ok(created_at) = chrono::DateTime::parse_from_rfc3339(&item.record.timestamp) {
            let age = (Utc::now() - created_at.with_timezone(&Utc))
                .num_seconds()
                .max(0) as u64;
            snapshot.oldest_age_seconds = Some(age);
        }
    }
    Ok(snapshot)
}

fn write_encrypted_permanent_quarantine(
    wal_dir: &std::path::Path,
    record: &event_wal::WalRecord,
    status: u16,
    response_body: &str,
    quarantine_key: &[u8; 32],
) -> Result<std::path::PathBuf, std::io::Error> {
    let quarantine_dir = wal_dir.join("quarantine");
    std::fs::create_dir_all(&quarantine_dir)?;
    let path = quarantine_dir.join(format!(
        "permanent-segment-{:010}-offset-{:020}.json",
        record.segment, record.offset
    ));
    if path.exists() {
        return Ok(path);
    }

    let retained = serde_json::json!({
        "wal_record": record,
        "response_body": response_body,
        "status": status,
    });
    let plaintext = serde_json::to_vec(&retained)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let (nonce_b64, ciphertext_b64) = encrypt_quarantine_payload(quarantine_key, &plaintext)?;
    let document = serde_json::json!({
        "schema": "encrypted-permanent-quarantine/v1",
        "segment": record.segment,
        "offset": record.offset,
        "event_id": record.event_id,
        "status": status,
        "wal_record_retained": true,
        "created_at": Utc::now().to_rfc3339(),
        "encrypted": {
            "alg": "AES-256-GCM",
            "nonce_b64": nonce_b64,
            "ciphertext_b64": ciphertext_b64,
        }
    });
    let encoded = serde_json::to_vec_pretty(&document)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let temporary = quarantine_dir.join(format!(
        ".permanent-segment-{:010}-offset-{:020}.tmp-{}-{}",
        record.segment,
        record.offset,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, &path)?;
    // Best-effort directory sync; failure must not drop the quarantine file.
    if let Ok(dir) = std::fs::File::open(&quarantine_dir) {
        let _ = dir.sync_all();
    }
    Ok(path)
}

fn required_text(value: &str, field: &'static str) -> Result<String, DurableEventError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(DurableEventError::InvalidField(field));
    }
    Ok(value.to_string())
}

fn payload_text(payload: &serde_json::Value, pointers: &[&str]) -> Option<String> {
    pointers.iter().find_map(|pointer| {
        payload
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

type SharedWalWriter = Arc<std::sync::Mutex<crate::gateway::event_wal::WalWriter>>;

struct SharedWalRuntime {
    writer: SharedWalWriter,
    notify: Arc<tokio::sync::Notify>,
    delivery_lock: Arc<tokio::sync::Mutex<()>>,
}

fn shared_wal_runtime() -> Result<Arc<SharedWalRuntime>, CliError> {
    static WRITERS: std::sync::LazyLock<
        std::sync::Mutex<HashMap<std::path::PathBuf, std::sync::Weak<SharedWalRuntime>>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

    let data_dir = std::env::var("VERDICTAN_DATA_DIR")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("verdictan"));
    let config = crate::gateway::event_wal::WalConfig::new(&data_dir).map_err(|error| {
        CliError::internal(format!("invalid durable event WAL config: {error}"))
    })?;
    let wal_dir = config.dir.clone();
    let mut writers = WRITERS
        .lock()
        .map_err(|_| CliError::internal("durable event WAL registry lock failed"))?;
    if let Some(runtime) = writers.get(&wal_dir).and_then(std::sync::Weak::upgrade) {
        return Ok(runtime);
    }

    let writer = crate::gateway::event_wal::WalWriter::open(config).map_err(|error| {
        CliError::internal(format!("failed to open durable event WAL: {error}"))
    })?;
    let runtime = Arc::new(SharedWalRuntime {
        writer: Arc::new(std::sync::Mutex::new(writer)),
        notify: Arc::new(tokio::sync::Notify::new()),
        delivery_lock: Arc::new(tokio::sync::Mutex::new(())),
    });
    writers.insert(wal_dir, Arc::downgrade(&runtime));
    Ok(runtime)
}

/// Fsync a durable decision envelope through the shared WAL without requiring
/// an upstream `EventSink` API configuration.
pub fn persist_durable_decision_local(
    request_id: &str,
    mut payload: serde_json::Value,
) -> Result<DurableEventEnvelope, DurableEventError> {
    let event_id = payload_text(
        &payload,
        &["/event_id", "/trail_event_id", "/metadata/event_id"],
    )
    .unwrap_or_else(|| format!("decision:{}", request_id.trim()));
    if let Some(object) = payload.as_object_mut() {
        object
            .entry("event_id")
            .or_insert_with(|| serde_json::Value::String(event_id));
        object
            .entry("timestamp")
            .or_insert_with(|| serde_json::Value::String(Utc::now().to_rfc3339()));
    }
    let envelope = DurableEventEnvelope::new(DurableEventKind::Decision, request_id, payload)?;
    let runtime = shared_wal_runtime().map_err(|error| {
        DurableEventError::WalWrite(format!("durable WAL runtime unavailable: {error}"))
    })?;
    let wal_payload = serde_json::to_value(&envelope)
        .map_err(|error| DurableEventError::Serialization(error.to_string()))?;
    runtime
        .writer
        .lock()
        .map_err(|_| DurableEventError::WalLock)?
        .append(envelope.delivery_id.clone(), wal_payload)
        .map_err(|error| DurableEventError::WalWrite(error.to_string()))?;
    runtime.notify.notify_one();
    Ok(envelope)
}

#[derive(Clone, Debug)]
pub struct EventSinkConfig {
    pub base_url: String,
    pub api_token: String,
    pub gateway_service_token: Option<String>,
}

impl EventSinkConfig {
    pub fn from_env() -> Result<Option<Self>, CliError> {
        let Some(base_url) = std::env::var("VERDICTAN_API_URL").ok() else {
            return Ok(None);
        };
        if base_url.trim().is_empty() {
            return Ok(None);
        }

        let Some(api_token) = optional_env("VERDICTAN_API_TOKEN") else {
            return Ok(None);
        };

        Ok(Some(Self {
            base_url,
            api_token: api_token.clone(),
            gateway_service_token: Some(api_token),
        }))
    }
}

#[derive(Clone)]
pub struct EventSink {
    pub base_url: String,
    pub client: reqwest::Client,
    pub machine_client: Option<reqwest::Client>,
    gateway_budget_absence_cache:
        Arc<BoundedTtlCache<ControlPlaneBudgetQueryCacheKey, Vec<GatewayBudgetRecord>>>,
    gateway_provider_budget_absence_cache: Arc<
        BoundedTtlCache<
            ControlPlaneProviderBudgetQueryCacheKey,
            GatewayProviderBudgetCheckResponse,
        >,
    >,
    runtime_routing_cache: Arc<BoundedTtlCache<String, RuntimeRoutingSettings>>,
    bound_gateway_agent_cache: Arc<BoundedTtlCache<String, Option<GatewayAgentSummary>>>,
    pub(super) access_preflight_cache:
        Arc<BoundedTtlCache<PreflightCacheKey, ConnectedAccessPreflightOutcome>>,
    /// Non-sliding usage-authorization policy-decision cache.
    /// Caches only the read-only evaluate document keyed by the request context;
    /// never authorizes and never bypasses the later commit/dispatch.
    pub(super) ua_policy_cache: Arc<usage_authorization_pipeline::UsageAuthorizationPolicyCache>,
    /// Phase 9: when true, redact message bodies before sending events.
    pub redact_message_bodies: bool,
    /// Bounded concurrency for WAL delivery.
    pub forward_semaphore: Arc<tokio::sync::Semaphore>,
    /// Shared counter of in-flight WAL delivery attempts.
    pub in_flight_tasks: Arc<std::sync::atomic::AtomicUsize>,
    /// JoinSet tracking the WAL worker so shutdown can abort it after draining.
    pub forward_join_set: Arc<std::sync::Mutex<tokio::task::JoinSet<()>>>,
    /// Shared append-only WAL writer. Every durable append completes `fsync`
    /// before this sink permits provider dispatch or starts API delivery.
    durable_wal_writer: SharedWalWriter,
    /// Prevent duplicate WAL appends for repeated legacy forwarding calls for
    /// the same logical event during the current process lifetime.
    persisted_event_ids: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    wal_notify: Arc<tokio::sync::Notify>,
    wal_delivery_lock: Arc<tokio::sync::Mutex<()>>,
    /// AES-256-GCM key for permanent-quarantine ciphertext at rest.
    quarantine_key: [u8; 32],
    _wal_runtime: Arc<SharedWalRuntime>,
}

impl std::fmt::Debug for EventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSink")
            .field("base_url", &self.base_url)
            .field("redact_message_bodies", &self.redact_message_bodies)
            .finish_non_exhaustive()
    }
}

impl EventSink {
    pub fn from_config(config: EventSinkConfig) -> Result<Self, CliError> {
        let base_url = config.base_url;
        let api_token = config.api_token;
        let gateway_service_token = config.gateway_service_token;

        let mut headers = reqwest::header::HeaderMap::new();
        let auth_value =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", api_token))
                .map_err(|_| CliError::user("api token contains invalid header characters"))?;
        headers.insert(reqwest::header::AUTHORIZATION, auth_value);

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| CliError::internal(format!("failed to build http client: {e}")))?;

        let machine_client = gateway_service_token
            .map(|token| {
                let mut headers = reqwest::header::HeaderMap::new();
                let auth_value =
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token)).map_err(
                        |_| CliError::user("service token contains invalid header characters"),
                    )?;
                headers.insert(reqwest::header::AUTHORIZATION, auth_value);

                reqwest::Client::builder()
                    .default_headers(headers)
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .map_err(|e| {
                        CliError::internal(format!(
                            "failed to build control-plane http client: {e}"
                        ))
                    })
            })
            .transpose()?;

        let wal_runtime = shared_wal_runtime()?;
        let quarantine_key = quarantine_key_from_token(&api_token);
        Ok(Self {
            base_url,
            client,
            machine_client,
            gateway_budget_absence_cache: Arc::new(BoundedTtlCache::new(
                2048,
                Duration::from_secs(10),
            )),
            gateway_provider_budget_absence_cache: Arc::new(BoundedTtlCache::new(
                2048,
                Duration::from_secs(10),
            )),
            runtime_routing_cache: Arc::new(BoundedTtlCache::new(256, RUNTIME_ROUTING_CACHE_TTL)),
            bound_gateway_agent_cache: Arc::new(BoundedTtlCache::new(
                256,
                BOUND_GATEWAY_AGENT_CACHE_TTL,
            )),
            access_preflight_cache: Arc::new(BoundedTtlCache::new(512, ACCESS_PREFLIGHT_CACHE_TTL)),
            ua_policy_cache: Arc::new(
                usage_authorization_pipeline::UsageAuthorizationPolicyCache::new(1024),
            ),
            redact_message_bodies: false,
            forward_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            in_flight_tasks: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            forward_join_set: Arc::new(std::sync::Mutex::new(tokio::task::JoinSet::new())),
            durable_wal_writer: Arc::clone(&wal_runtime.writer),
            persisted_event_ids: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            wal_notify: Arc::clone(&wal_runtime.notify),
            wal_delivery_lock: Arc::clone(&wal_runtime.delivery_lock),
            quarantine_key,
            _wal_runtime: wal_runtime,
        })
    }

    /// Phase 9: set whether this sink redacts message bodies before sending.
    pub(super) fn with_redact_bodies(mut self, redact: bool) -> Self {
        self.redact_message_bodies = redact;
        self
    }

    pub fn join_url(&self, path: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{base}/{path}")
    }

    /// Expose the underlying HTTP client for use by gateway sub-modules.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Return the base API URL this sink points at (no trailing slash).
    pub fn base_url(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }

    pub fn machine_client(&self) -> Result<&reqwest::Client, anyhow::Error> {
        self.machine_client.as_ref().ok_or_else(|| {
            anyhow::anyhow!("control-plane client is not configured: set VERDICTAN_API_TOKEN")
        })
    }

    pub(super) async fn validate_token(
        &self,
        raw_key: &str,
    ) -> Result<TokenValidationResponse, TokenValidationError> {
        let (client, path) = match &self.machine_client {
            Some(machine_client) => (machine_client, "/v1/gateway/tokens/validate"),
            None => (&self.client, "/v1/tokens/validate"),
        };

        let policy = crate::retry::RetryPolicy {
            max_retries: 2,
            base_delay: std::time::Duration::from_millis(50),
            multiplier: 2.0,
            max_delay: std::time::Duration::from_millis(200),
            jitter: 0.2,
        };
        let url = self.join_url(path);
        let raw_key_str = raw_key.to_string();

        crate::retry::with_retry_classified(
            &policy,
            "validate_token",
            |err| match err {
                TokenValidationError::Request(_) => crate::retry::RetryClassification::Transient,
                _ => crate::retry::RetryClassification::Permanent,
            },
            || {
                let url = url.clone();
                let raw_key_str = raw_key_str.clone();
                async move {
                    let response = client
                        .post(&url)
                        .json(&serde_json::json!({ "token": raw_key_str }))
                        .send()
                        .await
                        .map_err(TokenValidationError::Request)?;

                    if !response.status().is_success() {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        return Err(match status {
                            StatusCode::UNAUTHORIZED => TokenValidationError::Unauthorized { body },
                            StatusCode::FORBIDDEN => TokenValidationError::Forbidden { body },
                            _ => TokenValidationError::UnexpectedStatus { status, body },
                        });
                    }

                    response
                        .json::<TokenValidationResponse>()
                        .await
                        .map_err(TokenValidationError::Request)
                }
            },
        )
        .await
    }

    pub(super) async fn probe_token_validation(&self) -> Result<(), TokenValidationError> {
        let _ = self.validate_token("vdt_probe_invalid").await?;
        Ok(())
    }

    pub(super) async fn fetch_runtime_routing_settings(
        &self,
        org_id: Option<&str>,
    ) -> Result<RuntimeRoutingSettings, anyhow::Error> {
        let cache_key = org_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("__default__")
            .to_string();
        let lookup_start = Instant::now();
        if let Some(cached) = self.runtime_routing_cache.get(&cache_key) {
            self.runtime_routing_cache
                .insert(cache_key.clone(), cached.clone());
            record_request_stage_timing(
                RequestStageTiming::RuntimeRoutingLookup,
                lookup_start.elapsed(),
                Some(true),
            );
            return Ok(cached);
        }

        let (client, path) = match &self.machine_client {
            Some(machine_client) => (machine_client, "/v1/gateway/settings/runtime-routing"),
            None => (&self.client, "/v1/settings/runtime-routing"),
        };

        let response = match client.get(self.join_url(path)).send().await {
            Ok(response) => response,
            Err(error) => {
                record_request_stage_timing(
                    RequestStageTiming::RuntimeRoutingLookup,
                    lookup_start.elapsed(),
                    Some(false),
                );
                return Err(error.into());
            }
        };
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            record_request_stage_timing(
                RequestStageTiming::RuntimeRoutingLookup,
                lookup_start.elapsed(),
                Some(false),
            );
            anyhow::bail!("runtime routing settings lookup failed: status={status} body={body}");
        }

        let settings = match response.json::<RuntimeRoutingSettings>().await {
            Ok(settings) => settings,
            Err(error) => {
                record_request_stage_timing(
                    RequestStageTiming::RuntimeRoutingLookup,
                    lookup_start.elapsed(),
                    Some(false),
                );
                return Err(error.into());
            }
        };
        self.runtime_routing_cache
            .insert(cache_key, settings.clone());
        record_request_stage_timing(
            RequestStageTiming::RuntimeRoutingLookup,
            lookup_start.elapsed(),
            Some(false),
        );
        Ok(settings)
    }

    pub(super) async fn fetch_bound_gateway_agent_binding(
        &self,
        gateway_id: &str,
    ) -> Result<Option<GatewayAgentSummary>, String> {
        let cache_key = gateway_id.trim().to_string();
        let lookup_start = Instant::now();
        if let Some(cached) = self.bound_gateway_agent_cache.get(&cache_key) {
            self.bound_gateway_agent_cache
                .insert(cache_key.clone(), cached.clone());
            record_request_stage_timing(
                RequestStageTiming::BoundGatewayAgentLookup,
                lookup_start.elapsed(),
                Some(true),
            );
            return Ok(cached);
        }

        let url = self.join_url(&format!("/v1/gateways/{cache_key}/agents"));
        let response = match self.client().get(url).send().await {
            Ok(response) => response,
            Err(error) => {
                record_request_stage_timing(
                    RequestStageTiming::BoundGatewayAgentLookup,
                    lookup_start.elapsed(),
                    Some(false),
                );
                return Err(format!("gateway agent lookup request failed: {error}"));
            }
        };

        if !response.status().is_success() {
            record_request_stage_timing(
                RequestStageTiming::BoundGatewayAgentLookup,
                lookup_start.elapsed(),
                Some(false),
            );
            return Err(format!(
                "gateway agent lookup returned non-success status {}",
                response.status()
            ));
        }

        let agent = response
            .json::<GatewayAgentListResponse>()
            .await
            .map(|body| body.agents.into_iter().next())
            .map_err(|error| format!("gateway agent lookup response decode failed: {error}"));
        match agent {
            Ok(agent) => {
                self.bound_gateway_agent_cache
                    .insert(cache_key, agent.clone());
                record_request_stage_timing(
                    RequestStageTiming::BoundGatewayAgentLookup,
                    lookup_start.elapsed(),
                    Some(false),
                );
                Ok(agent)
            }
            Err(error) => {
                record_request_stage_timing(
                    RequestStageTiming::BoundGatewayAgentLookup,
                    lookup_start.elapsed(),
                    Some(false),
                );
                Err(error)
            }
        }
    }

    pub(super) async fn list_budgets(
        &self,
        target_type: &str,
        target_id: Option<&str>,
    ) -> Result<Vec<GatewayBudgetRecord>, anyhow::Error> {
        let mut url = reqwest::Url::parse(&self.join_url("/v1/budgets"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("target_type", target_type);
            if let Some(target_id) = target_id {
                query.append_pair("target_id", target_id);
            }
        }

        let response = self.client.get(url).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("budget lookup failed: status={status} body={body}");
        }

        Ok(response.json::<GatewayBudgetListResponse>().await?.budgets)
    }

    pub async fn list_control_plane_budgets(
        &self,
        org_id: &str,
        target_type: &str,
        target_id: Option<&str>,
        team_id: Option<&str>,
        user_id: Option<&str>,
        key_id: Option<&str>,
    ) -> Result<Vec<GatewayBudgetRecord>, anyhow::Error> {
        let cache_key = ControlPlaneBudgetQueryCacheKey {
            org_id: org_id.to_string(),
            target_type: target_type.to_string(),
            target_id: target_id.map(ToOwned::to_owned),
            team_id: team_id.map(ToOwned::to_owned),
            user_id: user_id.map(ToOwned::to_owned),
            key_id: key_id.map(ToOwned::to_owned),
        };
        if let Some(cached) = self.gateway_budget_absence_cache.get(&cache_key) {
            return Ok(cached);
        }

        let mut url = reqwest::Url::parse(&self.join_url("/v1/gateway/budgets"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("org_id", org_id);
            query.append_pair("target_type", target_type);
            if let Some(target_id) = target_id {
                query.append_pair("target_id", target_id);
            }
            if let Some(team_id) = team_id {
                query.append_pair("team_id", team_id);
            }
            if let Some(user_id) = user_id {
                query.append_pair("user_id", user_id);
            }
            if let Some(key_id) = key_id {
                query.append_pair("key_id", key_id);
            }
        }

        let response = self.machine_client()?.get(url).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("control-plane budget lookup failed: status={status} body={body}");
        }

        let budgets = response.json::<GatewayBudgetListResponse>().await?.budgets;
        if budgets.is_empty() {
            self.gateway_budget_absence_cache
                .insert(cache_key, budgets.clone());
        }

        Ok(budgets)
    }

    pub(super) async fn check_provider_budget(
        &self,
        provider: &str,
        model: Option<&str>,
    ) -> Result<GatewayProviderBudgetCheckResponse, anyhow::Error> {
        let mut url =
            reqwest::Url::parse(&self.join_url(&format!("/v1/provider-budgets/{provider}/check")))?;
        if let Some(model) = model {
            url.query_pairs_mut().append_pair("model", model);
        }

        let response = self.client.get(url).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("provider budget check failed: status={status} body={body}");
        }

        Ok(response
            .json::<GatewayProviderBudgetCheckResponse>()
            .await?)
    }

    pub async fn check_control_plane_provider_budget(
        &self,
        org_id: &str,
        provider: &str,
        model: Option<&str>,
        team_id: Option<&str>,
        user_id: Option<&str>,
        key_id: Option<&str>,
    ) -> Result<GatewayProviderBudgetCheckResponse, anyhow::Error> {
        let cache_key = ControlPlaneProviderBudgetQueryCacheKey {
            org_id: org_id.to_string(),
            provider: provider.to_string(),
            model: model.map(ToOwned::to_owned),
            team_id: team_id.map(ToOwned::to_owned),
            user_id: user_id.map(ToOwned::to_owned),
            key_id: key_id.map(ToOwned::to_owned),
        };
        if let Some(cached) = self.gateway_provider_budget_absence_cache.get(&cache_key) {
            return Ok(cached);
        }

        let mut url = reqwest::Url::parse(
            &self.join_url(&format!("/v1/gateway/provider-budgets/{provider}/check")),
        )?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("org_id", org_id);
            if let Some(model) = model {
                query.append_pair("model", model);
            }
            if let Some(team_id) = team_id {
                query.append_pair("team_id", team_id);
            }
            if let Some(user_id) = user_id {
                query.append_pair("user_id", user_id);
            }
            if let Some(key_id) = key_id {
                query.append_pair("key_id", key_id);
            }
        }

        let response = self.machine_client()?.get(url).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "control-plane provider budget check failed: status={status} body={body}"
            );
        }

        let budget = response
            .json::<GatewayProviderBudgetCheckResponse>()
            .await?;
        if budget.allowed && budget.remaining_budget.is_none() {
            self.gateway_provider_budget_absence_cache
                .insert(cache_key, budget.clone());
        }

        Ok(budget)
    }

    /// Fsync one logical event envelope to the WAL.
    ///
    /// Repeated calls for the same `event_id` in one gateway process are
    /// idempotent. The first successful append wins and later legacy forwarding
    /// calls may still deliver the richer API payload without creating a second
    /// durable logical event.
    pub fn persist_durable_event(
        &self,
        event_kind: DurableEventKind,
        request_id: &str,
        mut payload: serde_json::Value,
    ) -> Result<DurableEventEnvelope, DurableEventError> {
        if matches!(
            event_kind,
            DurableEventKind::Decision | DurableEventKind::Trail
        ) {
            let event_id = payload_text(
                &payload,
                &["/event_id", "/trail_event_id", "/metadata/event_id"],
            )
            .unwrap_or_else(|| format!("{}:{}", event_kind.as_str(), request_id.trim()));
            if let Some(object) = payload.as_object_mut() {
                object
                    .entry("event_id")
                    .or_insert_with(|| serde_json::Value::String(event_id));
                object
                    .entry("timestamp")
                    .or_insert_with(|| serde_json::Value::String(Utc::now().to_rfc3339()));
            }
        }
        let envelope = DurableEventEnvelope::new(event_kind, request_id, payload)?;
        let persistence_key = format!("{}:{}", event_kind.as_str(), envelope.event_id);
        let mut persisted_event_ids = self
            .persisted_event_ids
            .lock()
            .map_err(|_| DurableEventError::WalLock)?;
        if persisted_event_ids.contains(&persistence_key) {
            // First append already owns the durable logical event. Still forward
            // the richer superseding payload (post-dispatch correlation /
            // interruption / output policy evidence) over the API path.
            drop(persisted_event_ids);
            self.spawn_richer_payload_forward(envelope.clone());
            return Ok(envelope);
        }

        let wal_payload = serde_json::to_value(&envelope)
            .map_err(|error| DurableEventError::Serialization(error.to_string()))?;
        self.durable_wal_writer
            .lock()
            .map_err(|_| DurableEventError::WalLock)?
            .append(envelope.delivery_id.clone(), wal_payload)
            .map_err(|error| DurableEventError::WalWrite(error.to_string()))?;
        persisted_event_ids.insert(persistence_key);
        self.wal_notify.notify_one();

        tracing::debug!(
            delivery_id = %envelope.delivery_id,
            event_id = %envelope.event_id,
            event_kind = envelope.event_kind.as_str(),
            request_id = %envelope.request_id,
            "durable event envelope fsynced"
        );
        Ok(envelope)
    }

    /// Fsync an admitted policy decision before provider dispatch.
    pub fn persist_admitted_decision(
        &self,
        request_id: &str,
        payload: serde_json::Value,
    ) -> Result<DurableEventEnvelope, DurableEventError> {
        self.persist_durable_event(DurableEventKind::Decision, request_id, payload)
    }

    /// Fsync a spend event before starting its API delivery.
    pub fn persist_spend(
        &self,
        request_id: &str,
        payload: serde_json::Value,
    ) -> Result<DurableEventEnvelope, DurableEventError> {
        self.persist_durable_event(DurableEventKind::Spend, request_id, payload)
    }

    /// Fsync a typed spend-log payload through the durable spend seam.
    pub fn persist_spend_log(
        &self,
        request_id: &str,
        spend_log: &SpendLogPayload,
    ) -> Result<DurableEventEnvelope, DurableEventError> {
        let spend_payload = serde_json::to_value(spend_log)
            .map_err(|error| DurableEventError::Serialization(error.to_string()))?;
        self.persist_spend(request_id, spend_payload)
    }

    /// Fsync an AI-usage event through the common durable envelope seam.
    pub fn persist_ai_usage(
        &self,
        request_id: &str,
        payload: serde_json::Value,
    ) -> Result<DurableEventEnvelope, DurableEventError> {
        self.persist_durable_event(DurableEventKind::AiUsage, request_id, payload)
    }

    /// Fsync a Trail event through the common durable envelope seam.
    pub fn persist_trail(
        &self,
        request_id: &str,
        payload: serde_json::Value,
    ) -> Result<DurableEventEnvelope, DurableEventError> {
        self.persist_durable_event(DurableEventKind::Trail, request_id, payload)
    }

    /// Fsync an immutable usage-authorization completion payload.
    pub fn persist_ua_complete(
        &self,
        request_id: &str,
        gateway_usage_authorization_id: &str,
        complete_request: &usage_authorization::UsageAuthorizationCompleteRequest,
        event_id: &str,
    ) -> Result<DurableEventEnvelope, DurableEventError> {
        let complete_request = serde_json::to_value(complete_request)
            .map_err(|error| DurableEventError::Serialization(error.to_string()))?;
        let payload = serde_json::json!({
            "event_id": event_id,
            "gateway_usage_authorization_id": gateway_usage_authorization_id,
            "complete_request": complete_request,
        });
        self.persist_durable_event(DurableEventKind::UaComplete, request_id, payload)
    }

    /// Persist and immediately deliver a UA completion envelope inline (no warn-only spawn).
    pub async fn persist_and_deliver_ua_complete(
        &self,
        request_id: &str,
        gateway_usage_authorization_id: &str,
        complete_request: &usage_authorization::UsageAuthorizationCompleteRequest,
        event_id: &str,
    ) -> Result<(), UaFinancialWalError> {
        let envelope = self
            .persist_ua_complete(
                request_id,
                gateway_usage_authorization_id,
                complete_request,
                event_id,
            )
            .map_err(UaFinancialWalError::Persist)?;
        self.deliver_envelope_inline(&envelope)
            .await
            .map_err(UaFinancialWalError::Delivery)?;
        Ok(())
    }

    /// Deliver one durable envelope inline without spawning a detached retry loop.
    pub async fn deliver_envelope_inline(
        &self,
        envelope: &DurableEventEnvelope,
    ) -> Result<(), String> {
        let record = event_wal::WalRecord {
            event_id: envelope.event_id.clone(),
            timestamp: envelope.created_at.clone(),
            segment: 0,
            offset: 0,
            checksum: event_wal::WalRecord::compute_checksum(
                &serde_json::to_value(envelope).map_err(|error| error.to_string())?,
            ),
            payload: serde_json::to_value(envelope).map_err(|error| error.to_string())?,
        };
        match self.deliver_wal_record(&record).await {
            DeliveryDisposition::Accepted => Ok(()),
            DeliveryDisposition::Retry { reason } => Err(reason),
            DeliveryDisposition::Permanent { status, body } => Err(format!(
                "permanent delivery rejection: status={status} body={body}"
            )),
        }
    }

    /// Fsync a decision event envelope (metrics + optional body redaction).
    ///
    /// Prefer [`Self::persist_admitted_decision`] before upstream dispatch and
    /// [`Self::persist_durable_event`] for explicit kind control.
    pub fn persist_decision_event(
        &self,
        request_id: &str,
        mut event: serde_json::Value,
    ) -> Result<DurableEventEnvelope, DurableEventError> {
        let provider = event
            .pointer("/details/runtime/provider")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let verdict = event
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("allow");
        let status: u16 = if verdict == "block" { 409 } else { 200 };
        metrics::record_request("POST", status, provider);

        if self.redact_message_bodies {
            redact_event_message_bodies(&mut event);
        }
        self.persist_durable_event(DurableEventKind::Decision, request_id, event)
    }

    /// Persist a decision event via the WAL delivery API (void call-site helper).
    pub fn enqueue_decision(&self, request_id: &str, event: serde_json::Value) {
        if let Err(error) = self.persist_decision_event(request_id, event) {
            tracing::error!(
                request_id = %request_id,
                error = %error,
                "decision event delivery blocked because WAL fsync failed"
            );
            metrics::EVENTS_DROPPED_COUNTER.inc();
        }
    }

    /// Best-effort API forward for a richer superseding payload when the logical
    /// `event_id` was already fsynced earlier in this process (e.g. pre-dispatch
    /// admission followed by post-dispatch outcome evidence).
    fn spawn_richer_payload_forward(&self, envelope: DurableEventEnvelope) {
        let sink = self.clone();
        match self.forward_join_set.lock() {
            Ok(mut join_set) => {
                join_set.spawn(async move {
                    let disposition = sink.deliver_envelope_once(&envelope).await;
                    if !matches!(disposition, DeliveryDisposition::Accepted) {
                        tracing::warn!(
                            request_id = %envelope.request_id,
                            event_id = %envelope.event_id,
                            delivery_id = %envelope.delivery_id,
                            ?disposition,
                            "richer superseding event payload forward did not accept"
                        );
                    }
                });
            }
            Err(error) => {
                tracing::error!(
                    request_id = %envelope.request_id,
                    error = %error,
                    "richer payload forward join set lock failed"
                );
            }
        }
    }

    async fn deliver_envelope_once(&self, envelope: &DurableEventEnvelope) -> DeliveryDisposition {
        let payload = match serde_json::to_value(envelope) {
            Ok(value) => value,
            Err(error) => {
                return DeliveryDisposition::Permanent {
                    status: 422,
                    body: format!("invalid richer envelope: {error}"),
                };
            }
        };
        let record = event_wal::WalRecord {
            event_id: envelope.event_id.clone(),
            timestamp: envelope.created_at.clone(),
            segment: 0,
            offset: 0,
            checksum: event_wal::WalRecord::compute_checksum(&payload),
            payload,
        };
        self.deliver_wal_record(&record).await
    }

    /// Persist a spend log via the WAL delivery API (void call-site helper).
    pub fn enqueue_spend_log(&self, request_id: &str, spend_log: SpendLogPayload) {
        if let Err(error) = self.persist_spend_log(request_id, &spend_log) {
            tracing::error!(
                request_id = %request_id,
                error = %error,
                "spend log delivery blocked because WAL fsync failed"
            );
        }
    }

    pub async fn ingest_event(
        &self,
        request_id: &str,
        _traceparent: &str,
        event: serde_json::Value,
    ) -> Result<(), anyhow::Error> {
        self.persist_decision_event(request_id, event)
            .map(|_| ())
            .map_err(anyhow::Error::new)
    }

    async fn run_wal_delivery_loop(self) {
        let policy = wal_delivery_retry_policy();
        let mut retry_attempt = 0u32;
        loop {
            let delivery_guard = self.wal_delivery_lock.lock().await;
            let writer = Arc::clone(&self.durable_wal_writer);
            let next = tokio::task::spawn_blocking(move || {
                let writer = writer
                    .lock()
                    .map_err(|_| std::io::Error::other("durable event WAL lock failed"))?;
                let checkpoint = writer.checkpoint()?;
                writer.next_pending(&checkpoint)
            })
            .await;

            let item = match next {
                Ok(Ok(Some(item))) => item,
                Ok(Ok(None)) => {
                    drop(delivery_guard);
                    tokio::select! {
                        () = self.wal_notify.notified() => {}
                        () = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                    retry_attempt = 0;
                    continue;
                }
                Ok(Err(error)) => {
                    drop(delivery_guard);
                    tracing::error!(error = %error, "durable event WAL read failed closed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                Err(error) => {
                    drop(delivery_guard);
                    tracing::error!(error = %error, "durable event WAL reader task failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            // Keep the delivery lock only for claim → send → ack/quarantine.
            // Release before backoff sleeps so a restarted worker can take over
            // the shared WAL runtime without waiting out the prior delay.
            let retry_sleep = match item {
                event_wal::PendingItem::Quarantined(item) => {
                    tracing::error!(
                        segment = item.segment,
                        offset = item.offset,
                        reason = %item.reason,
                        "malformed durable event quarantined"
                    );
                    if let Err(error) = self
                        .acknowledge_wal_item(item.next_segment, item.next_offset)
                        .await
                    {
                        tracing::error!(error = %error, "failed to checkpoint quarantined WAL item");
                        Some(Duration::from_secs(1))
                    } else {
                        None
                    }
                }
                event_wal::PendingItem::Record(item) => {
                    match self.deliver_wal_record(&item.record).await {
                        DeliveryDisposition::Accepted => {
                            if let Err(error) = self
                                .acknowledge_wal_item(item.next_segment, item.next_offset)
                                .await
                            {
                                tracing::error!(
                                    event_id = %item.record.event_id,
                                    error = %error,
                                    "event accepted but WAL checkpoint failed; delivery will replay"
                                );
                                retry_attempt = retry_attempt.saturating_add(1);
                                DELIVERY_RETRIES_TOTAL.fetch_add(1, AtomicOrdering::Relaxed);
                                metrics::record_audit_delivery_retry();
                                Some(compute_delay(&policy, retry_attempt.max(1)))
                            } else {
                                DELIVERY_LAST_SUCCESS_UNIX
                                    .store(Utc::now().timestamp(), AtomicOrdering::Relaxed);
                                metrics::record_audit_delivery_success();
                                retry_attempt = 0;
                                None
                            }
                        }
                        DeliveryDisposition::Retry { reason } => {
                            retry_attempt = retry_attempt.saturating_add(1);
                            DELIVERY_RETRIES_TOTAL.fetch_add(1, AtomicOrdering::Relaxed);
                            metrics::record_audit_delivery_retry();
                            let delay = compute_delay(&policy, retry_attempt.max(1));
                            tracing::warn!(
                                event_id = %item.record.event_id,
                                reason = %reason,
                                attempt = retry_attempt,
                                delay_ms = delay.as_millis(),
                                "durable event delivery will retry"
                            );
                            Some(delay)
                        }
                        DeliveryDisposition::Permanent { status, body } => {
                            let writer = Arc::clone(&self.durable_wal_writer);
                            let record = item.record.clone();
                            let quarantine_key = self.quarantine_key;
                            let next_segment = item.next_segment;
                            let next_offset = item.next_offset;
                            let quarantine = tokio::task::spawn_blocking(move || {
                                let mut writer = writer.lock().map_err(|_| {
                                    std::io::Error::other("durable event WAL lock failed")
                                })?;
                                let data_dir = std::env::var("VERDICTAN_DATA_DIR")
                                    .ok()
                                    .map(std::path::PathBuf::from)
                                    .unwrap_or_else(|| std::env::temp_dir().join("verdictan"));
                                let wal_dir = data_dir.join("event-retry");
                                // Encrypted quarantine retains the full WAL record. Advance the
                                // delivery frontier so later valid records can progress; readiness
                                // stays blocked until the quarantine document is corrected.
                                write_encrypted_permanent_quarantine(
                                    &wal_dir,
                                    &record,
                                    status,
                                    &body,
                                    &quarantine_key,
                                )?;
                                writer.acknowledge(next_segment, next_offset)?;
                                Ok::<_, std::io::Error>(())
                            })
                            .await;
                            match quarantine {
                                Ok(Ok(())) => {
                                    DELIVERY_QUARANTINE_TOTAL.fetch_add(1, AtomicOrdering::Relaxed);
                                    metrics::record_audit_delivery_quarantine();
                                    tracing::error!(
                                        event_id = %item.record.event_id,
                                        status,
                                        "permanently rejected event quarantined encrypted; readiness blocked until corrected"
                                    );
                                    retry_attempt = 0;
                                    None
                                }
                                Ok(Err(error)) => {
                                    tracing::error!(
                                        event_id = %item.record.event_id,
                                        error = %error,
                                        "failed to quarantine permanently rejected event"
                                    );
                                    Some(Duration::from_secs(1))
                                }
                                Err(error) => {
                                    tracing::error!(
                                        event_id = %item.record.event_id,
                                        error = %error,
                                        "permanent-rejection quarantine task failed"
                                    );
                                    Some(Duration::from_secs(1))
                                }
                            }
                        }
                    }
                }
            };
            drop(delivery_guard);
            if let Some(delay) = retry_sleep {
                tokio::time::sleep(delay).await;
            }
        }
    }

    async fn acknowledge_wal_item(
        &self,
        next_segment: u64,
        next_offset: u64,
    ) -> Result<(), std::io::Error> {
        let writer = Arc::clone(&self.durable_wal_writer);
        tokio::task::spawn_blocking(move || {
            writer
                .lock()
                .map_err(|_| std::io::Error::other("durable event WAL lock failed"))?
                .acknowledge(next_segment, next_offset)
                .map(|_| ())
        })
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?
    }

    async fn deliver_wal_record(&self, record: &event_wal::WalRecord) -> DeliveryDisposition {
        let envelope = match serde_json::from_value::<DurableEventEnvelope>(record.payload.clone())
        {
            Ok(envelope) => envelope,
            Err(error) => {
                return DeliveryDisposition::Permanent {
                    status: 422,
                    body: format!("invalid durable envelope: {error}"),
                };
            }
        };
        let envelope_json = serde_json::to_value(&envelope).unwrap_or(envelope.payload.clone());
        let (path, client, json_body): (String, &reqwest::Client, serde_json::Value) =
            match envelope.event_kind {
                DurableEventKind::Spend => {
                    if let Some(machine_client) = self.machine_client.as_ref() {
                        (
                            "/v1/gateway/spend/log".to_string(),
                            machine_client,
                            envelope_json,
                        )
                    } else {
                        ("/v1/spend/log".to_string(), &self.client, envelope_json)
                    }
                }
                DurableEventKind::UaComplete => {
                    let gateway_usage_authorization_id =
                        ua_authorization_id_from_payload(&envelope.payload).unwrap_or_default();
                    let complete_request = ua_complete_request_from_payload(&envelope.payload)
                        .unwrap_or(envelope.payload.clone());
                    let path = format!(
                        "/v1/gateway/usage-authorizations/{gateway_usage_authorization_id}/complete"
                    );
                    if let Some(machine_client) = self.machine_client.as_ref() {
                        (path, machine_client, complete_request)
                    } else {
                        return DeliveryDisposition::Permanent {
                            status: 503,
                            body: "usage-authorization completion delivery requires machine client"
                                .to_string(),
                        };
                    }
                }
                DurableEventKind::Decision
                | DurableEventKind::AiUsage
                | DurableEventKind::Trail => {
                    if let Some(machine_client) = self.machine_client.as_ref() {
                        (
                            "/v1/gateway/events".to_string(),
                            machine_client,
                            envelope_json,
                        )
                    } else {
                        ("/v1/events".to_string(), &self.client, envelope_json)
                    }
                }
            };
        let permit = match Arc::clone(&self.forward_semaphore).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                return DeliveryDisposition::Retry {
                    reason: "delivery semaphore closed".to_string(),
                };
            }
        };
        self.in_flight_tasks
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let request = client
            .post(self.join_url(&path))
            .header("X-Request-Id", &envelope.request_id)
            .header("Idempotency-Key", &envelope.event_id)
            .header("X-Verdictan-Delivery-Id", &envelope.delivery_id)
            .timeout(event_wal::RESPONSE_TIMEOUT)
            .json(&json_body);
        let response = match tokio::time::timeout(event_wal::ATTEMPT_DEADLINE, request.send()).await
        {
            Ok(result) => result,
            Err(_) => {
                self.in_flight_tasks
                    .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                drop(permit);
                return DeliveryDisposition::Retry {
                    reason: format!(
                        "delivery attempt deadline exceeded ({:?})",
                        event_wal::ATTEMPT_DEADLINE
                    ),
                };
            }
        };

        self.in_flight_tasks
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        drop(permit);

        match response {
            Ok(response) => {
                let status = response.status();
                let mut body = match tokio::time::timeout(
                    event_wal::RESPONSE_TIMEOUT,
                    response.text(),
                )
                .await
                {
                    Ok(Ok(body)) => body,
                    Ok(Err(error)) => {
                        return DeliveryDisposition::Retry {
                            reason: format!("response body read failed: {error}"),
                        };
                    }
                    Err(_) => {
                        return DeliveryDisposition::Retry {
                            reason: "response body read deadline exceeded".to_string(),
                        };
                    }
                };
                body.truncate(4096);

                if status.is_success() {
                    match extract_ack_delivery_id(&body) {
                        Some(ack_id) if ack_id == envelope.delivery_id => {
                            DeliveryDisposition::Accepted
                        }
                        Some(ack_id) => DeliveryDisposition::Retry {
                            reason: format!(
                                "2xx ack delivery_id mismatch: expected {} got {ack_id}",
                                envelope.delivery_id
                            ),
                        },
                        None => DeliveryDisposition::Retry {
                            reason: "2xx ack missing matching delivery_id".to_string(),
                        },
                    }
                } else {
                    match classify_http_delivery_status(status) {
                        DeliveryDisposition::Retry { reason } => {
                            DeliveryDisposition::Retry { reason }
                        }
                        DeliveryDisposition::Permanent { status, .. } => {
                            DeliveryDisposition::Permanent { status, body }
                        }
                        DeliveryDisposition::Accepted => DeliveryDisposition::Retry {
                            reason: "unexpected accepted classification for non-2xx".to_string(),
                        },
                    }
                }
            }
            Err(error) => DeliveryDisposition::Retry {
                reason: error.to_string(),
            },
        }
    }

    pub async fn create_agent_review_execution(
        &self,
        request_id: &str,
        traceparent: &str,
        agent_id: &str,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, anyhow::Error> {
        let url = self.join_url(&format!("/v1/agents/{agent_id}/review-executions"));
        let response = self
            .client()
            .post(url)
            .header("X-Request-Id", request_id)
            .header("traceparent", traceparent)
            .json(payload)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("review execution persist failed: status={status} body={body}");
        }

        Ok(response.json::<serde_json::Value>().await?)
    }
}

/// Start the durable WAL delivery worker for this sink (idempotent per process sink).
pub fn spawn_wal_delivery_worker(event_sink: Option<&EventSink>) {
    if let Some(sink) = event_sink {
        let worker = sink.clone();
        #[allow(clippy::expect_used)]
        sink.forward_join_set
            .lock()
            .expect("forward join set lock")
            .spawn(worker.run_wal_delivery_loop());
        sink.wal_notify.notify_one();
    }
}

/// Await in-flight WAL delivery tasks on gateway shutdown (5s timeout, then abort).
pub async fn drain_forwarding_tasks_on_shutdown(
    shutdown_join_set: Option<Arc<std::sync::Mutex<tokio::task::JoinSet<()>>>>,
) {
    if let Some(join_set_mutex) = shutdown_join_set {
        #[allow(clippy::expect_used)]
        let mut join_set = {
            let mut guard = join_set_mutex.lock().expect("forward join set lock");
            std::mem::take(&mut *guard)
        };
        let task_count = join_set.len();
        if task_count == 0 {
            tracing::info!("shutdown drain: no in-flight forwarding tasks");
        } else {
            tracing::info!(
                task_count = task_count,
                "shutdown drain: awaiting in-flight forwarding tasks (5s timeout)"
            );
            match tokio::time::timeout(Duration::from_secs(5), async {
                while join_set.join_next().await.is_some() {}
            })
            .await
            {
                Ok(()) => {
                    tracing::info!("shutdown drain: all in-flight tasks completed");
                }
                Err(_) => {
                    let remaining = join_set.len();
                    tracing::warn!(
                        remaining_tasks = remaining,
                        "shutdown drain: timeout reached, aborting remaining tasks"
                    );
                    join_set.abort_all();
                }
            }
        }
    }
}

pub struct GatewayHandle {
    pub addr: std::net::SocketAddr,
    pub(super) shutdown: tokio::sync::oneshot::Sender<()>,
}

impl GatewayHandle {
    pub fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

#[cfg(test)]
mod durable_envelope_tests {
    use super::{DurableEventEnvelope, DurableEventError, DurableEventKind};
    use sha2::{Digest, Sha256};

    #[test]
    fn envelope_binds_required_fields_and_payload_digest() {
        let payload = serde_json::json!({
            "event_id": "evt-1",
            "org_id": "org-1",
            "team_id": "team-1",
            "created_at": "2026-08-01T12:00:00Z",
            "verdict": "allow"
        });
        let envelope = DurableEventEnvelope::new(DurableEventKind::Decision, "req-1", payload)
            .expect("envelope");
        assert!(!envelope.delivery_id.is_empty());
        assert_eq!(envelope.event_id, "evt-1");
        assert_eq!(envelope.event_kind, DurableEventKind::Decision);
        assert_eq!(envelope.org_id.as_deref(), Some("org-1"));
        assert_eq!(envelope.team_id.as_deref(), Some("team-1"));
        assert_eq!(envelope.request_id, "req-1");
        assert_eq!(envelope.created_at, "2026-08-01T12:00:00Z");
        let digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&envelope.payload).expect("serialize"),
        ));
        assert_eq!(envelope.payload_sha256, digest);
    }

    #[test]
    fn envelope_kinds_cover_decision_spend_ai_usage_trail_and_ua_completion() {
        for (kind, label) in [
            (DurableEventKind::Decision, "decision"),
            (DurableEventKind::Spend, "spend"),
            (DurableEventKind::AiUsage, "ai_usage"),
            (DurableEventKind::Trail, "trail"),
            (DurableEventKind::UaComplete, "ua_complete"),
        ] {
            assert_eq!(kind.as_str(), label);
            let envelope = DurableEventEnvelope::new(
                kind,
                "req-kind",
                serde_json::json!({"record_id": format!("{label}-1")}),
            )
            .expect("envelope");
            assert_eq!(envelope.event_kind, kind);
            assert_eq!(envelope.event_id, format!("{label}-1"));
        }
    }

    #[test]
    fn envelope_rejects_empty_request_id() {
        let err = DurableEventEnvelope::new(
            DurableEventKind::Spend,
            "  ",
            serde_json::json!({"id": "spend-1"}),
        )
        .expect_err("empty request_id");
        assert!(matches!(err, DurableEventError::InvalidField("request_id")));
    }

    #[test]
    fn ua_authorization_id_reads_gateway_usage_authorization_id() {
        let payload = serde_json::json!({
            "gateway_usage_authorization_id": "auth-1"
        });
        assert_eq!(
            super::ua_authorization_id_from_payload(&payload).as_deref(),
            Some("auth-1")
        );
    }

    #[test]
    fn ua_authorization_id_ignores_legacy_reservation_id() {
        let payload = serde_json::json!({ "reservation_id": "legacy-1" });
        assert_eq!(super::ua_authorization_id_from_payload(&payload), None);
    }

    #[test]
    fn ua_completion_payload_uses_gateway_usage_authorization_id() {
        let envelope = DurableEventEnvelope::new(
            DurableEventKind::UaComplete,
            "req-ua",
            serde_json::json!({
                "event_id": "evt-ua",
                "gateway_usage_authorization_id": "auth-42",
                "complete_request": { "state": "completed" }
            }),
        )
        .expect("envelope");
        assert_eq!(
            envelope.payload["gateway_usage_authorization_id"],
            serde_json::json!("auth-42")
        );
        assert!(envelope.payload.get("reservation_id").is_none());
        assert!(envelope.payload.get("stage_event").is_none());
    }

    #[test]
    fn durable_kind_marks_only_usage_authorization_completion() {
        assert!(DurableEventKind::UaComplete.is_usage_authorization_completion());
        for kind in [
            DurableEventKind::Decision,
            DurableEventKind::Spend,
            DurableEventKind::AiUsage,
            DurableEventKind::Trail,
        ] {
            assert!(!kind.is_usage_authorization_completion());
        }
    }
}

#[cfg(test)]
mod wal_delivery_worker_tests {
    use super::*;
    use crate::retry::compute_delay_with_sample;
    use std::sync::atomic::Ordering;

    #[test]
    fn retry_policy_is_bounded_exponential_with_jitter() {
        let policy = wal_delivery_retry_policy();
        assert_eq!(policy.base_delay, Duration::from_millis(100));
        assert_eq!(policy.max_delay, Duration::from_secs(5));
        assert!((policy.multiplier - 2.0).abs() < f64::EPSILON);
        assert!((policy.jitter - 0.25).abs() < f64::EPSILON);

        let low = compute_delay_with_sample(&policy, 1, 0.0);
        let high = compute_delay_with_sample(&policy, 1, 0.999);
        assert!(low <= Duration::from_millis(100));
        assert!(high >= Duration::from_millis(100));
        assert!(high <= Duration::from_millis(125));

        let capped = compute_delay_with_sample(&policy, 20, 0.5);
        assert!(capped <= Duration::from_secs(5));
    }

    #[test]
    fn http_status_matrix_replays_network_class_and_quarantines_other_4xx() {
        assert!(matches!(
            classify_http_delivery_status(reqwest::StatusCode::REQUEST_TIMEOUT),
            DeliveryDisposition::Retry { .. }
        ));
        assert!(matches!(
            classify_http_delivery_status(reqwest::StatusCode::TOO_MANY_REQUESTS),
            DeliveryDisposition::Retry { .. }
        ));
        assert!(matches!(
            classify_http_delivery_status(reqwest::StatusCode::SERVICE_UNAVAILABLE),
            DeliveryDisposition::Retry { .. }
        ));
        assert!(matches!(
            classify_http_delivery_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            DeliveryDisposition::Retry { .. }
        ));
        match classify_http_delivery_status(reqwest::StatusCode::INSUFFICIENT_STORAGE) {
            DeliveryDisposition::Permanent { status, .. } => assert_eq!(status, 507),
            other => panic!("expected permanent, got {other:?}"),
        }
        match classify_http_delivery_status(reqwest::StatusCode::UNPROCESSABLE_ENTITY) {
            DeliveryDisposition::Permanent { status, .. } => assert_eq!(status, 422),
            other => panic!("expected permanent, got {other:?}"),
        }
        match classify_http_delivery_status(reqwest::StatusCode::UNAUTHORIZED) {
            DeliveryDisposition::Permanent { status, .. } => assert_eq!(status, 401),
            other => panic!("expected permanent, got {other:?}"),
        }
        assert!(matches!(
            classify_http_delivery_status(reqwest::StatusCode::ACCEPTED),
            DeliveryDisposition::Accepted
        ));
    }

    #[test]
    fn ack_requires_matching_delivery_id() {
        assert_eq!(
            extract_ack_delivery_id(r#"{"accepted":true,"delivery_id":"abc"}"#).as_deref(),
            Some("abc")
        );
        assert_eq!(
            extract_ack_delivery_id(r#"{"accepted":true,"event_id":"evt"}"#),
            None
        );
    }

    #[test]
    fn encrypted_quarantine_retains_wal_record_and_blocks_readiness() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = crate::test_support::env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::test_support::set_var("VERDICTAN_DATA_DIR", dir.path());

        let wal_dir = dir.path().join("event-retry");
        std::fs::create_dir_all(wal_dir.join("quarantine")).expect("quarantine dir");
        let record = event_wal::WalRecord {
            event_id: "evt-q".to_string(),
            timestamp: "2026-08-01T00:00:00Z".to_string(),
            segment: 0,
            offset: 42,
            checksum: 1,
            payload: serde_json::json!({
                "delivery_id": "11111111-1111-1111-1111-111111111111",
                "event_id": "evt-q",
                "event_kind": "decision",
                "request_id": "req-q",
                "created_at": "2026-08-01T00:00:00Z",
                "payload_sha256": "a".repeat(64),
                "payload": {"event_type": "decision"}
            }),
        };
        let key = quarantine_key_from_token("test-token");
        write_encrypted_permanent_quarantine(&wal_dir, &record, 422, "invalid", &key)
            .expect("quarantine");

        assert!(quarantine_blocks_readiness());
        let snapshot = snapshot_audit_wal_delivery().expect("snapshot");
        assert_eq!(snapshot.quarantine_pending, 1);
        assert!(snapshot.readiness_blocked_by_quarantine);

        let path = wal_dir
            .join("quarantine")
            .join("permanent-segment-0000000000-offset-00000000000000000042.json");
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
        assert_eq!(document["schema"], "encrypted-permanent-quarantine/v1");
        assert_eq!(document["wal_record_retained"], true);
        assert!(document.get("payload").is_none());
        let nonce = document["encrypted"]["nonce_b64"].as_str().expect("nonce");
        let ciphertext = document["encrypted"]["ciphertext_b64"]
            .as_str()
            .expect("ciphertext");
        let plaintext = decrypt_quarantine_payload(&key, nonce, ciphertext).expect("decrypt");
        let retained: serde_json::Value = serde_json::from_slice(&plaintext).expect("retained");
        assert_eq!(retained["wal_record"]["event_id"], "evt-q");
        assert_eq!(retained["wal_record"]["offset"], 42);
        assert_eq!(retained["status"], 422);

        assert!(acknowledge_corrected_quarantine(0, 42).expect("ack"));
        assert!(!quarantine_blocks_readiness());
        crate::test_support::unset_var("VERDICTAN_DATA_DIR");
    }

    #[test]
    fn attempt_deadline_constant_is_tighter_than_drain_tick() {
        assert_eq!(event_wal::ATTEMPT_DEADLINE, Duration::from_secs(15));
        assert!(event_wal::RESPONSE_TIMEOUT <= event_wal::ATTEMPT_DEADLINE);
        assert!(event_wal::CONNECT_TIMEOUT <= event_wal::ATTEMPT_DEADLINE);
    }

    #[test]
    fn snapshot_exposes_retry_and_success_counters() {
        let before = DELIVERY_RETRIES_TOTAL.load(Ordering::Relaxed);
        DELIVERY_RETRIES_TOTAL.fetch_add(1, Ordering::Relaxed);
        DELIVERY_LAST_SUCCESS_UNIX.store(1_725_000_000, Ordering::Relaxed);
        let snapshot = snapshot_audit_wal_delivery().expect("snapshot");
        assert!(snapshot.delivery_retries_total > before);
        assert_eq!(snapshot.delivery_last_success_unix, Some(1_725_000_000));
    }
}

//: the durable authorization completion log keeps a neutral outcome
/// body, addresses the renamed usage-authorization route, and stays idempotent
/// across replays.
#[cfg(test)]
mod usage_authorization_completion_delivery_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use axum::{
        extract::Path, http::HeaderMap, response::IntoResponse, routing::post, Json, Router,
    };
    use std::sync::atomic::{AtomicUsize, Ordering as TestOrdering};

    #[derive(Clone, Debug)]
    struct RecordedCompletion {
        authorization_id: String,
        idempotency_key: String,
        delivery_id: String,
        body: serde_json::Value,
    }

    struct CompletionApi {
        base_url: String,
        recorded: Arc<std::sync::Mutex<Vec<RecordedCompletion>>>,
        task: tokio::task::JoinHandle<()>,
    }

    /// Mock control plane for the usage-authorization completion route. The
    /// first `failures_before_success` attempts answer `503` so the delivery
    /// path must replay the identical envelope.
    async fn start_completion_api(failures_before_success: usize) -> CompletionApi {
        let recorded: Arc<std::sync::Mutex<Vec<RecordedCompletion>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let attempts = Arc::new(AtomicUsize::new(0));
        let handler_recorded = Arc::clone(&recorded);
        let handler_attempts = Arc::clone(&attempts);

        let app = Router::new().route(
            "/v1/gateway/usage-authorizations/:gateway_usage_authorization_id/complete",
            post(
                move |Path(authorization_id): Path<String>,
                      headers: HeaderMap,
                      Json(body): Json<serde_json::Value>| {
                    let recorded = Arc::clone(&handler_recorded);
                    let attempts = Arc::clone(&handler_attempts);
                    async move {
                        let header_text = |name: &str| {
                            headers
                                .get(name)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_string()
                        };
                        let delivery_id = header_text("X-Verdictan-Delivery-Id");
                        recorded
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(RecordedCompletion {
                                authorization_id,
                                idempotency_key: header_text("Idempotency-Key"),
                                delivery_id: delivery_id.clone(),
                                body,
                            });

                        let attempt = attempts.fetch_add(1, TestOrdering::SeqCst);
                        if attempt < failures_before_success {
                            return (
                                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                                Json(serde_json::json!({ "error": "control plane unavailable" })),
                            )
                                .into_response();
                        }
                        (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({
                                "accepted": true,
                                "delivery_id": delivery_id,
                            })),
                        )
                            .into_response()
                    }
                },
            ),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind completion api");
        let addr = listener.local_addr().expect("completion api addr");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve completion api");
        });

        CompletionApi {
            base_url: format!("http://{addr}"),
            recorded,
            task,
        }
    }

    fn completion_envelope(request_id: &str, authorization_id: &str) -> DurableEventEnvelope {
        let complete_request = serde_json::to_value(
            usage_authorization::UsageAuthorizationCompleteRequest::Completed {
                input_tokens: 100,
                output_tokens: 20,
                cached_input_tokens: None,
                pricing_snapshot_id: None,
            },
        )
        .expect("serialize complete request");
        DurableEventEnvelope::new(
            DurableEventKind::UaComplete,
            request_id,
            serde_json::json!({
                "event_id": format!("evt-{authorization_id}"),
                "gateway_usage_authorization_id": authorization_id,
                "complete_request": complete_request,
            }),
        )
        .expect("completion envelope")
    }

    fn sink_for(base_url: &str) -> EventSink {
        EventSink::from_config(EventSinkConfig {
            base_url: base_url.to_string(),
            api_token: "user-token".to_string(),
            gateway_service_token: Some("machine-token".to_string()),
        })
        .expect("event sink")
    }

    #[tokio::test]
    async fn completion_delivery_repeats_the_same_idempotency_identity_on_every_attempt() {
        let api = start_completion_api(0).await;
        let sink = sink_for(&api.base_url);
        let envelope = completion_envelope("req-ua-idempotent", "auth-idempotent");

        sink.deliver_envelope_inline(&envelope)
            .await
            .expect("first delivery accepted");
        sink.deliver_envelope_inline(&envelope)
            .await
            .expect("repeat delivery accepted");

        let recorded = api
            .recorded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert_eq!(recorded.len(), 2, "both attempts must reach the same route");
        for attempt in &recorded {
            assert_eq!(
                attempt.authorization_id, "auth-idempotent",
                "delivery must address the usage-authorization completion route"
            );
            assert_eq!(
                attempt.idempotency_key, envelope.event_id,
                "the idempotency key must stay bound to the logical event id"
            );
            assert_eq!(
                attempt.delivery_id, envelope.delivery_id,
                "a repeated delivery must not mint a new delivery id"
            );
        }
        assert_eq!(
            recorded[0].body, recorded[1].body,
            "a repeated delivery must send a byte-identical completion body"
        );

        let body = &recorded[0].body;
        assert_eq!(body["outcome"], serde_json::json!("completed"));
        assert_eq!(body["input_tokens"], serde_json::json!(100));
        assert!(
            body.get("stage_event").is_none(),
            "provider-billing stage events are removed"
        );
        assert!(
            body.get("billing_state").is_none(),
            "billing-pending outcomes are removed"
        );
        for removed in crate::gateway::removed_provider_access_contract::REMOVED_COMPLETION_FIELDS {
            assert!(
                body.get(removed).is_none(),
                "credential-vault cache records are removed: {removed}"
            );
        }

        api.task.abort();
    }

    #[tokio::test]
    async fn completion_delivery_replays_the_identical_envelope_after_a_retryable_status() {
        let api = start_completion_api(1).await;
        let sink = sink_for(&api.base_url);
        let envelope = completion_envelope("req-ua-replay", "auth-replay");

        let first = sink
            .deliver_envelope_inline(&envelope)
            .await
            .expect_err("503 must not acknowledge the completion");
        assert!(
            !first.contains("permanent delivery rejection"),
            "a 503 must classify as replay, got {first}"
        );

        sink.deliver_envelope_inline(&envelope)
            .await
            .expect("replay is accepted once the control plane recovers");

        let recorded = api
            .recorded
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert_eq!(recorded.len(), 2, "the failed attempt must be replayed");
        assert_eq!(recorded[0].delivery_id, recorded[1].delivery_id);
        assert_eq!(recorded[0].idempotency_key, recorded[1].idempotency_key);
        assert_eq!(recorded[0].body, recorded[1].body);

        api.task.abort();
    }

    #[tokio::test]
    async fn completion_delivery_is_refused_without_a_control_plane_machine_client() {
        let api = start_completion_api(0).await;
        let sink = EventSink::from_config(EventSinkConfig {
            base_url: api.base_url.clone(),
            api_token: "user-token".to_string(),
            gateway_service_token: None,
        })
        .expect("event sink");
        let envelope = completion_envelope("req-ua-no-machine", "auth-no-machine");

        let error = sink
            .deliver_envelope_inline(&envelope)
            .await
            .expect_err("completion delivery requires the machine client");
        assert!(
            error.contains("usage-authorization completion delivery requires machine client"),
            "unexpected error: {error}"
        );
        assert!(
            api.recorded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty(),
            "a refused completion must not reach the control plane"
        );

        api.task.abort();
    }
}
