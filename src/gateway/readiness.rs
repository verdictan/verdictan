// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Gateway readiness and distributed-bootstrap.
//!
//! This module owns:
//! - [`DistributedReadinessBootstrap`] and
//!   [`initialize_distributed_state_and_rollout`] (including
//!   `rollout_grade_required` computation)
//! - Connected-mode dependency health evaluation via
//!   [`evaluate_connected_dependency_health`]
//! - Probe handlers [`proxy_health`], [`proxy_liveness`], and
//!   [`proxy_readiness`] used by `/healthz`, `/livez`, and `/readyz`
//!
//! [`DistributedRequirement::Required`] fails startup on missing URL
//! or initialization failure; runtime backend loss returns `/readyz` 503 with
//! `dependency.distributed_state_unavailable` and blocks dependent requests via
//! the same reason code. Connected-mode must not silently fall back to
//! process-local distributed state.

use super::*;
use crate::gateway::distributed_state::{
    DistributedPolicyCapabilities, DistributedRequirement, DistributedStateUnavailable,
    DISTRIBUTED_STATE_UNAVAILABLE_REASON,
};
use crate::gateway::{cache, distributed_state, metrics};

/// Bootstrap outputs for distributed state plus connected-mode rollout grade.
#[derive(Debug)]
pub(super) struct DistributedReadinessBootstrap {
    pub distributed_state: Option<Arc<distributed_state::DistributedState>>,
    pub rollout_grade_required: bool,
    pub rollout_grade: bool,
    pub rollout_grade_reasons: Vec<String>,
    pub distributed_requirement: DistributedRequirement,
}

/// Stable reason codes and context for a failed connected-mode dependency check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ConnectedDependencyHealthIssue {
    MissingEventSink,
    TokenValidationProbeFailed(String),
    PublicationCatalogStale {
        last_successful_refresh_at: Option<DateTime<Utc>>,
        last_refresh_error: Option<String>,
        stale_after_secs: i64,
    },
    RoutingCompatibilityStale {
        last_successful_refresh_at: Option<DateTime<Utc>>,
        last_refresh_error: Option<String>,
        stale_after_secs: i64,
    },
    ManagedPublicEndpointNotAdmissible {
        publication_key: String,
        published_hostname: Option<String>,
        publication_state: String,
        issue: String,
    },
}

impl ConnectedDependencyHealthIssue {
    fn log_and_status(&self) -> StatusCode {
        match self {
            Self::MissingEventSink => {
                tracing::warn!(
                    "connected gateway readiness failed: missing Verdictan API event sink"
                );
            }
            Self::TokenValidationProbeFailed(error) => {
                tracing::warn!(
                    error = %error,
                    "connected gateway readiness failed: API token validation probe failed"
                );
            }
            Self::PublicationCatalogStale {
                last_successful_refresh_at,
                last_refresh_error,
                stale_after_secs,
            } => {
                tracing::warn!(
                    publication_catalog_last_successful_refresh_at = ?last_successful_refresh_at,
                    publication_catalog_last_refresh_error = ?last_refresh_error,
                    stale_after_secs = stale_after_secs,
                    "connected gateway readiness failed: publication catalog feed is stale"
                );
            }
            Self::RoutingCompatibilityStale {
                last_successful_refresh_at,
                last_refresh_error,
                stale_after_secs,
            } => {
                tracing::warn!(
                    routing_compatibility_last_successful_refresh_at = ?last_successful_refresh_at,
                    routing_compatibility_last_refresh_error = ?last_refresh_error,
                    stale_after_secs = stale_after_secs,
                    "connected gateway readiness failed: routing compatibility feed is stale"
                );
            }
            Self::ManagedPublicEndpointNotAdmissible {
                publication_key,
                published_hostname,
                publication_state,
                issue,
            } => {
                tracing::warn!(
                    publication_key = %publication_key,
                    published_hostname = ?published_hostname,
                    publication_state = %publication_state,
                    readiness_issue = issue,
                    "connected gateway readiness failed: managed public endpoint publication is not publicly admissible"
                );
            }
        }
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Fail-closed audit WAL readiness issues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AuditWalHealthIssue {
    WalFull,
    WalUnwritable,
    CorruptCheckpoint,
    QuarantineNonEmpty { files: u64 },
}

impl AuditWalHealthIssue {
    fn from_snapshot(snapshot: &metrics::AuditWalSnapshot) -> Option<Self> {
        if !snapshot.readiness_blocked() {
            return None;
        }
        if snapshot.corrupt_checkpoint {
            return Some(Self::CorruptCheckpoint);
        }
        if snapshot.wal_unwritable {
            return Some(Self::WalUnwritable);
        }
        if snapshot.wal_full {
            return Some(Self::WalFull);
        }
        if snapshot.quarantine_non_empty {
            return Some(Self::QuarantineNonEmpty {
                files: snapshot.quarantine_files,
            });
        }
        None
    }

    fn reason_code(&self) -> &'static str {
        match self {
            Self::WalFull => "audit.wal_full",
            Self::WalUnwritable => "audit.wal_unwritable",
            Self::CorruptCheckpoint => "audit.wal_corrupt_checkpoint",
            Self::QuarantineNonEmpty { .. } => "audit.wal_quarantine_non_empty",
        }
    }

    fn log_and_status(&self) -> StatusCode {
        match self {
            Self::WalFull => {
                tracing::warn!(
                    reason = self.reason_code(),
                    "audit-required readiness failed: audit WAL is full"
                );
            }
            Self::WalUnwritable => {
                tracing::warn!(
                    reason = self.reason_code(),
                    "audit-required readiness failed: audit WAL is unwritable"
                );
            }
            Self::CorruptCheckpoint => {
                tracing::warn!(
                    reason = self.reason_code(),
                    "audit-required readiness failed: audit WAL checkpoint is corrupt"
                );
            }
            Self::QuarantineNonEmpty { files } => {
                tracing::warn!(
                    reason = self.reason_code(),
                    quarantine_files = files,
                    "audit-required readiness failed: audit WAL quarantine is non-empty"
                );
            }
        }
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Required distributed-state readiness failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DistributedStateHealthIssue {
    backend_name: &'static str,
    detail: String,
}

impl DistributedStateHealthIssue {
    fn from_unavailable(error: DistributedStateUnavailable) -> Self {
        Self {
            backend_name: error.backend_name(),
            detail: error.detail().to_string(),
        }
    }

    fn reason_code(&self) -> &'static str {
        DISTRIBUTED_STATE_UNAVAILABLE_REASON
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "status": "not_ready",
            "error": {
                "code": self.reason_code(),
                "message": format!(
                    "required distributed state ({}) unavailable: {}",
                    self.backend_name, self.detail
                ),
                "backend": self.backend_name,
            }
        })
    }

    fn log_and_response(&self) -> (StatusCode, Json<serde_json::Value>) {
        tracing::warn!(
            reason = self.reason_code(),
            backend = self.backend_name,
            detail = %self.detail,
            "distributed-state readiness failed: required backend unavailable"
        );
        (StatusCode::SERVICE_UNAVAILABLE, Json(self.to_json()))
    }
}

/// Audit durability is required when the gateway is connected or has an event sink.
pub(super) fn audit_required(state: &GatewayState) -> bool {
    state.connected_mode || state.event_sink.is_some()
}

/// Evaluate audit WAL health for readiness. Always refreshes audit metrics.
pub(super) fn evaluate_audit_wal_health(
    audit_required: bool,
) -> Result<metrics::AuditWalSnapshot, AuditWalHealthIssue> {
    evaluate_audit_wal_health_at(audit_required, &metrics::audit_wal_data_dir())
}

/// Evaluate audit WAL health for an explicit data-dir root (test seam).
pub(super) fn evaluate_audit_wal_health_at(
    audit_required: bool,
    data_dir: &std::path::Path,
) -> Result<metrics::AuditWalSnapshot, AuditWalHealthIssue> {
    let snapshot = metrics::observe_audit_wal_at(data_dir);
    if audit_required {
        if let Some(issue) = AuditWalHealthIssue::from_snapshot(&snapshot) {
            tracing::warn!(
                wal_dir = %snapshot.wal_dir.display(),
                reason = issue.reason_code(),
                "audit WAL readiness observation blocked"
            );
            return Err(issue);
        }
    }
    Ok(snapshot)
}

/// Evaluate required distributed-state health for readiness and dependent requests.
pub(super) fn evaluate_distributed_state_health(
    distributed_state: Option<&distributed_state::DistributedState>,
) -> Result<(), DistributedStateHealthIssue> {
    let Some(state) = distributed_state else {
        return Ok(());
    };
    if !state.requirement().requires_live_backend() {
        return Ok(());
    }
    state
        .probe_backend()
        .map_err(DistributedStateHealthIssue::from_unavailable)?;
    state
        .ensure_available_for_dependent_request()
        .map_err(DistributedStateHealthIssue::from_unavailable)
}

/// Enforce live distributed state for dependent request admission.
///
/// Returns `Ok()` when the request may proceed. On required-backend loss,
/// returns the stable unavailable reason used for HTTP 503 responses.
pub(super) fn enforce_required_distributed_state_for_request(
    distributed_state: Option<&distributed_state::DistributedState>,
) -> Result<(), DistributedStateUnavailable> {
    let Some(state) = distributed_state else {
        return Ok(());
    };
    state.ensure_available_for_dependent_request()
}

/// Compute rollout grade flags without initializing backends.
///
/// `rollout_grade_required` is true when the immutable distributed requirement
/// needs a live backend that was established at startup (or legacy connected
/// mode with a live distributed backend). `rollout_grade` requires both
/// distributed readiness and a shared cache backend when rollout grade is
/// required; local/disabled requirements always report ready.
pub(super) fn compute_rollout_grade(
    connected_mode: bool,
    distributed_ready: bool,
    shared_cache_ready: bool,
    shared_cache_backend_name: &str,
    requirement: DistributedRequirement,
) -> (bool, bool, Vec<String>) {
    let rollout_grade_required =
        requirement.requires_live_backend() || (connected_mode && distributed_ready);
    let needs_rollout_backends = requirement.requires_live_backend() || connected_mode;
    let rollout_grade = !needs_rollout_backends || (distributed_ready && shared_cache_ready);
    let mut rollout_grade_reasons = Vec::new();
    if needs_rollout_backends {
        if !distributed_ready {
            rollout_grade_reasons.push("distributed_rate_limit_not_configured".to_string());
        }
        if !shared_cache_ready {
            rollout_grade_reasons.push(format!(
                "shared_cache_backend_required:{shared_cache_backend_name}"
            ));
        }
    }
    (rollout_grade_required, rollout_grade, rollout_grade_reasons)
}

/// Derive enabled required-state consumers from declarative/runtime config.
pub(super) fn policy_capabilities_from_runtime(
    config: &crate::runtime::RuntimeInstanceConfig,
    provider_cache: &cache::ProviderResponseCache,
) -> DistributedPolicyCapabilities {
    let loaded = &config.loaded_config;
    let rate_limits = loaded.distributed_rate_limit.is_some() || loaded.global_rate_limit.is_some();
    let budgets = loaded.budget_policy.is_some() || loaded.tool_budget.is_some();
    let fingerprints = loaded.fingerprint.is_some();
    let shared_cache_admission = provider_cache.uses_shared_backend()
        || loaded
            .workflow_cache
            .as_ref()
            .map(|wc| wc.enabled && wc.org_shared_enabled)
            .unwrap_or(false);
    let replay_protection = loaded
        .workflow_cache
        .as_ref()
        .map(|wc| {
            wc.enabled
                && (wc.direct_semantic_replay_enabled
                    || wc.allow_cross_provider_replay
                    || wc.require_approval_for_reuse)
        })
        .unwrap_or(false);
    DistributedPolicyCapabilities::from_enabled_flags(
        rate_limits,
        budgets,
        fingerprints,
        shared_cache_admission,
        replay_protection,
    )
}

/// Resolve deployment-mode label for distributed requirement derivation.
fn deployment_mode_for_requirement(connected_mode: bool) -> String {
    std::env::var("VERDICTAN_DEPLOYMENT_MODE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            if connected_mode {
                "connected".to_string()
            } else {
                "self-hosted".to_string()
            }
        })
}

pub(super) fn first_managed_public_endpoint_health_issue(
    snapshot: &ConnectedGatewayReadModelSnapshot,
) -> Option<(
    crate::runtime::ConnectedGatewayPublicationDescriptor,
    String,
)> {
    snapshot.publication_catalog.iter().find_map(|publication| {
        let materialized = materialize_connected_publication(snapshot, publication);
        let issue = publication_public_binding_issue(&materialized)?;
        Some((materialized, issue))
    })
}

/// Initialize optional distributed state and derive rollout-grade flags.
///
//: missing URL or initialization failure fails startup when the
/// derived requirement is [`DistributedRequirement::Required`]. Connected mode
/// never silently falls back to process-local distributed state when a
/// distributed backend is configured.
pub(super) async fn initialize_distributed_state_and_rollout(
    config: &crate::runtime::RuntimeInstanceConfig,
    provider_cache: &Arc<cache::ProviderResponseCache>,
) -> Result<DistributedReadinessBootstrap, CliError> {
    let capabilities = policy_capabilities_from_runtime(config, provider_cache);
    let verdictan_env = std::env::var("VERDICTAN_ENV").unwrap_or_default();
    let deployment_mode = deployment_mode_for_requirement(config.connected_mode);
    let requirement = DistributedRequirement::derive_from_runtime(
        config.connected_mode,
        &verdictan_env,
        &deployment_mode,
        capabilities,
    );

    let shared_distributed_cfg = config.loaded_config.distributed_rate_limit.clone();
    let refuse_local_fallback = requirement.requires_live_backend() || config.connected_mode;

    let distributed_state = if let Some(dist_cfg) = &shared_distributed_cfg {
        let url_env = dist_cfg.backend.url_env();
        let redis_url = std::env::var(url_env).unwrap_or_default();
        let redis_url_opt = if redis_url.trim().is_empty() {
            None
        } else {
            Some(redis_url.as_str())
        };

        if refuse_local_fallback && redis_url_opt.is_none() {
            return Err(CliError::user(format!(
                "distributed state is required (requirement={}, connected_mode={}) but \
                 backend URL env var '{url_env}' is missing or empty; set the URL or \
                 disable distributed consumers",
                requirement.as_str(),
                config.connected_mode
            )));
        }

        match distributed_state::DistributedState::initialize(
            redis_url_opt,
            dist_cfg.backend.as_str(),
            requirement,
        )
        .await
        {
            Ok(ds) => {
                if refuse_local_fallback && !ds.is_distributed() {
                    return Err(CliError::user(format!(
                        "distributed state is required (requirement={}) but backend \
                         '{}' did not become distributed; check '{url_env}' and rebuild \
                         with --features distributed if needed",
                        requirement.as_str(),
                        dist_cfg.backend.as_str()
                    )));
                }
                if !ds.is_distributed() {
                    tracing::info!(
                        backend = %dist_cfg.backend.as_str(),
                        requirement = requirement.as_str(),
                        url_env = %url_env,
                        "distributed backend URL unset; operating under local-only contract"
                    );
                }
                Some(Arc::new(ds))
            }
            Err(e) => {
                if refuse_local_fallback {
                    return Err(CliError::user(format!(
                        "failed to initialize required distributed state \
                         (requirement={}, backend={}, url_env={url_env}): {e}",
                        requirement.as_str(),
                        dist_cfg.backend.as_str()
                    )));
                }
                // LocalOnly / Disabled without connected mode: keep a local
                // state handle so consumers still have a process-local seam.
                tracing::warn!(
                    backend = %dist_cfg.backend.as_str(),
                    requirement = requirement.as_str(),
                    error = %e,
                    url_env = %url_env,
                    "failed to initialize distributed backend; continuing under local-only contract"
                );
                Some(Arc::new(
                    distributed_state::DistributedState::initialize(
                        None,
                        dist_cfg.backend.as_str(),
                        requirement,
                    )
                    .await
                    .map_err(|error| {
                        CliError::internal(format!(
                            "failed to initialize local-only distributed state: {error}"
                        ))
                    })?,
                ))
            }
        }
    } else if requirement.requires_live_backend() {
        return Err(CliError::user(format!(
            "distributed state is required (requirement={}) but no distributed backend \
             is configured in policy; add a distributed_rate_limit backend with a URL \
             env var",
            requirement.as_str()
        )));
    } else {
        None
    };

    let distributed_ready = distributed_state
        .as_ref()
        .map(|state| state.is_distributed())
        .unwrap_or(false);
    let shared_cache_ready = provider_cache.uses_shared_backend();
    let (rollout_grade_required, rollout_grade, rollout_grade_reasons) = compute_rollout_grade(
        config.connected_mode,
        distributed_ready,
        shared_cache_ready,
        provider_cache.backend_name(),
        requirement,
    );

    Ok(DistributedReadinessBootstrap {
        distributed_state,
        rollout_grade_required,
        rollout_grade,
        rollout_grade_reasons,
        distributed_requirement: requirement,
    })
}

/// Evaluate connected-mode control-plane and publication dependency health.
///
/// Local (non-connected) gateways always pass. Connected gateways require a
/// live event sink, successful token validation probe, fresh publication and
/// routing feeds, and publicly admissible managed endpoint publications.
pub(super) async fn evaluate_connected_dependency_health(
    state: &GatewayState,
) -> Result<(), ConnectedDependencyHealthIssue> {
    if !state.connected_mode {
        return Ok(());
    }

    let Some(sink) = state.event_sink.as_ref() else {
        return Err(ConnectedDependencyHealthIssue::MissingEventSink);
    };

    if let Err(error) = sink.probe_token_validation().await {
        return Err(ConnectedDependencyHealthIssue::TokenValidationProbeFailed(
            error.to_string(),
        ));
    }

    let connected_read_model = state.connected_read_model.snapshot();
    let now = Utc::now();
    if connected_read_model.publication_catalog_is_stale(now) {
        return Err(ConnectedDependencyHealthIssue::PublicationCatalogStale {
            last_successful_refresh_at: connected_read_model
                .publication_catalog_last_successful_refresh_at,
            last_refresh_error: connected_read_model
                .publication_catalog_last_refresh_error
                .clone(),
            stale_after_secs: connected_read_model.stale_after_secs(),
        });
    }

    if connected_read_model.routing_compatibility_is_stale(now) {
        return Err(ConnectedDependencyHealthIssue::RoutingCompatibilityStale {
            last_successful_refresh_at: connected_read_model
                .routing_compatibility_last_successful_refresh_at,
            last_refresh_error: connected_read_model
                .routing_compatibility_last_refresh_error
                .clone(),
            stale_after_secs: connected_read_model.stale_after_secs(),
        });
    }

    if let Some((publication, issue)) =
        first_managed_public_endpoint_health_issue(&connected_read_model)
    {
        return Err(
            ConnectedDependencyHealthIssue::ManagedPublicEndpointNotAdmissible {
                publication_key: publication.publication_key,
                published_hostname: publication.published_hostname,
                publication_state: publication.publication_state,
                issue,
            },
        );
    }

    Ok(())
}

/// Liveness + basic status (`/healthz`).
pub(super) async fn proxy_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// Liveness probe — always returns 200 if the process is up (`/livez`).
pub(super) async fn proxy_liveness() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "alive" }))
}

/// Readiness probe (`/readyz`) — dependency health plus rollout-grade metadata.
///
/// Required distributed-state loss returns HTTP 503 with
/// [`DISTRIBUTED_STATE_UNAVAILABLE_REASON`] in the JSON body.
pub(super) async fn proxy_readiness(
    State(state): State<GatewayState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(issue) = evaluate_connected_dependency_health(&state).await {
        let status = issue.log_and_status();
        return Err((
            status,
            Json(serde_json::json!({
                "status": "not_ready",
                "error": { "code": "dependency.connected_control_plane_unavailable" }
            })),
        ));
    }

    if let Err(issue) = evaluate_distributed_state_health(state.distributed_state.as_deref()) {
        return Err(issue.log_and_response());
    }

    let audit_snapshot = match evaluate_audit_wal_health(audit_required(&state)) {
        Ok(snapshot) => snapshot,
        Err(issue) => {
            let status = issue.log_and_status();
            return Err((
                status,
                Json(serde_json::json!({
                    "status": "not_ready",
                    "error": { "code": issue.reason_code() }
                })),
            ));
        }
    };

    let distributed_requirement = state
        .distributed_state
        .as_ref()
        .map(|ds| ds.requirement())
        .unwrap_or(crate::gateway::distributed_state::DistributedRequirement::Disabled);

    Ok(Json(serde_json::json!({
        "status": "ready",
        "rollout_grade": state.rollout_grade,
        "rollout_grade_required": state.rollout_grade_required,
        "rollout_grade_reasons": *state.rollout_grade_reasons,
        "distributed_requirement": distributed_requirement.as_str(),
        "distributed_local_only_guarantee": crate::gateway::distributed_rate_limit::local_only_guarantee_boundary(
            distributed_requirement,
        ),
        "gateway_runtime_metrics": state.gateway_runtime_metrics.as_json(),
        "audit_wal": audit_snapshot.metrics_json(),
        "audit_wal_records": audit_snapshot.audit_wal_records,
        "audit_wal_bytes": audit_snapshot.audit_wal_bytes,
        "audit_wal_oldest_age_seconds": audit_snapshot.audit_wal_oldest_age_seconds,
        "audit_delivery_retries_total": audit_snapshot.audit_delivery_retries_total,
        "audit_delivery_quarantine_total": audit_snapshot.audit_delivery_quarantine_total,
        "audit_delivery_last_success_timestamp": audit_snapshot.audit_delivery_last_success_timestamp,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::metrics::{self, AuditWalSnapshot};
    use std::path::PathBuf;

    fn sample_snapshot(blocked_field: &str) -> AuditWalSnapshot {
        let mut snapshot = AuditWalSnapshot {
            audit_wal_records: 3,
            audit_wal_bytes: 128,
            audit_wal_oldest_age_seconds: 12.0,
            audit_delivery_retries_total: 1.0,
            audit_delivery_quarantine_total: 0.0,
            audit_delivery_last_success_timestamp: 1_700_000_000.0,
            wal_full: false,
            wal_unwritable: false,
            corrupt_checkpoint: false,
            quarantine_non_empty: false,
            quarantine_files: 0,
            wal_dir: PathBuf::from("/tmp/verdictan-test-event-retry"),
        };
        match blocked_field {
            "full" => snapshot.wal_full = true,
            "unwritable" => snapshot.wal_unwritable = true,
            "corrupt" => snapshot.corrupt_checkpoint = true,
            "quarantine" => {
                snapshot.quarantine_non_empty = true;
                snapshot.quarantine_files = 2;
            }
            _ => {}
        }
        snapshot
    }

    #[test]
    fn local_mode_is_rollout_ready_without_distributed_backends() {
        let (required, grade, reasons) = compute_rollout_grade(
            false,
            false,
            false,
            "memory",
            DistributedRequirement::Disabled,
        );
        assert!(!required);
        assert!(grade);
        assert!(reasons.is_empty());
    }

    #[test]
    fn connected_mode_requires_distributed_and_shared_cache() {
        let (required, grade, reasons) =
            compute_rollout_grade(true, true, true, "redis", DistributedRequirement::Required);
        assert!(required);
        assert!(grade);
        assert!(reasons.is_empty());
    }

    #[test]
    fn connected_mode_reports_missing_distributed_and_shared_cache() {
        let (required, grade, reasons) = compute_rollout_grade(
            true,
            false,
            false,
            "memory",
            DistributedRequirement::Required,
        );
        assert!(required);
        assert!(!grade);
        assert_eq!(
            reasons,
            vec![
                "distributed_rate_limit_not_configured".to_string(),
                "shared_cache_backend_required:memory".to_string(),
            ]
        );
    }

    #[test]
    fn connected_distributed_without_shared_cache_keeps_required_true() {
        let (required, grade, reasons) = compute_rollout_grade(
            true,
            true,
            false,
            "memory",
            DistributedRequirement::Required,
        );
        assert!(required);
        assert!(!grade);
        assert_eq!(
            reasons,
            vec!["shared_cache_backend_required:memory".to_string()]
        );
    }

    #[test]
    fn required_requirement_forces_rollout_grade_without_connected_mode() {
        let (required, grade, reasons) =
            compute_rollout_grade(false, true, true, "redis", DistributedRequirement::Required);
        assert!(required);
        assert!(grade);
        assert!(reasons.is_empty());
    }

    #[test]
    fn distributed_state_health_issue_maps_to_503_reason() {
        let issue = DistributedStateHealthIssue::from_unavailable(
            DistributedStateUnavailable::new("redis", "probe failed"),
        );
        assert_eq!(issue.reason_code(), DISTRIBUTED_STATE_UNAVAILABLE_REASON);
        let (status, Json(body)) = issue.log_and_response();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], DISTRIBUTED_STATE_UNAVAILABLE_REASON);
        assert_eq!(body["status"], "not_ready");
    }

    #[tokio::test]
    async fn enforce_required_distributed_state_blocks_after_runtime_failure() {
        let state = distributed_state::DistributedState::initialize(
            None,
            "redis",
            DistributedRequirement::LocalOnly,
        )
        .await
        .expect("local only");
        assert!(enforce_required_distributed_state_for_request(Some(&state)).is_ok());

        #[cfg(feature = "distributed")]
        {
            let client = redis::Client::open("redis://127.0.0.1:1/").expect("client");
            let required =
                distributed_state::DistributedState::from_redis_client_for_tests_with_requirement(
                    Some(client),
                    "redis",
                    DistributedRequirement::Required,
                );
            required.mark_backend_failure();
            let err = enforce_required_distributed_state_for_request(Some(&required))
                .expect_err("required must fail closed");
            assert_eq!(err.reason_code(), DISTRIBUTED_STATE_UNAVAILABLE_REASON);
            assert_eq!(err.status_code(), 503);
            let (http_status, body) = err.to_http_parts();
            assert_eq!(http_status, 503);
            assert_eq!(body["error"]["code"], DISTRIBUTED_STATE_UNAVAILABLE_REASON);
            let health_err =
                evaluate_distributed_state_health(Some(&required)).expect_err("readyz");
            assert_eq!(
                health_err.reason_code(),
                DISTRIBUTED_STATE_UNAVAILABLE_REASON
            );
            let (status, Json(ready_body)) = health_err.log_and_response();
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                ready_body["error"]["code"],
                DISTRIBUTED_STATE_UNAVAILABLE_REASON
            );
        }
    }

    fn readiness_runtime_config(
        connected_mode: bool,
        loaded_config: crate::gateway::declarative_config::LoadedDeclarativeConfig,
    ) -> crate::runtime::RuntimeInstanceConfig {
        crate::runtime::RuntimeInstanceConfig::new(
            None,
            "127.0.0.1:0".parse().expect("listen"),
            "http://example.test".to_string(),
            None,
            crate::gateway::fail_mode::FailMode::Block,
            loaded_config,
            4,
            true,
            None,
        )
        .with_connected_mode(connected_mode)
    }

    #[tokio::test]
    async fn connected_mode_missing_distributed_url_fails_startup_without_local_fallback() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let url_env = "VERDICTAN_TEST_LANE046_CONNECTED_REDIS_URL";
        std::env::remove_var(url_env);

        let mut loaded = crate::gateway::declarative_config::LoadedDeclarativeConfig::empty();
        loaded.distributed_rate_limit =
            Some(crate::gateway::distributed_rate_limit::DistributedConfig {
                backend: crate::gateway::distributed_rate_limit::DistributedBackend::Redis {
                    url_env: url_env.to_string(),
                },
            });
        let config = readiness_runtime_config(true, loaded);
        let cache = Arc::new(cache::ProviderResponseCache::memory_for_test());
        let err = initialize_distributed_state_and_rollout(&config, &cache)
            .await
            .expect_err("connected mode must not fall back to local state");
        let msg = err.to_string();
        assert!(
            msg.contains(url_env) || msg.contains("missing") || msg.contains("empty"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("connected_mode=true") || msg.contains("required"),
            "error should cite connected/required contract: {msg}"
        );
    }

    #[tokio::test]
    async fn required_without_distributed_backend_config_fails_startup() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let previous_env = std::env::var("VERDICTAN_ENV").ok();
        let previous_mode = std::env::var("VERDICTAN_DEPLOYMENT_MODE").ok();
        std::env::set_var("VERDICTAN_ENV", "production");
        std::env::set_var("VERDICTAN_DEPLOYMENT_MODE", "self-hosted");

        let mut loaded = crate::gateway::declarative_config::LoadedDeclarativeConfig::empty();
        loaded.global_rate_limit = Some(crate::gateway::rate_limit::GlobalRateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
        });
        let config = readiness_runtime_config(false, loaded);
        let cache = Arc::new(cache::ProviderResponseCache::memory_for_test());
        let err = initialize_distributed_state_and_rollout(&config, &cache)
            .await
            .expect_err("Required must fail when no distributed backend is configured");
        let msg = err.to_string();
        assert!(
            msg.contains("required") && msg.contains("distributed"),
            "unexpected error: {msg}"
        );

        match previous_env {
            Some(value) => std::env::set_var("VERDICTAN_ENV", value),
            None => std::env::remove_var("VERDICTAN_ENV"),
        }
        match previous_mode {
            Some(value) => std::env::set_var("VERDICTAN_DEPLOYMENT_MODE", value),
            None => std::env::remove_var("VERDICTAN_DEPLOYMENT_MODE"),
        }
    }

    #[tokio::test]
    async fn local_only_missing_url_keeps_process_local_contract() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let previous_env = std::env::var("VERDICTAN_ENV").ok();
        let previous_mode = std::env::var("VERDICTAN_DEPLOYMENT_MODE").ok();
        std::env::set_var("VERDICTAN_ENV", "development");
        std::env::set_var("VERDICTAN_DEPLOYMENT_MODE", "self-hosted");
        let url_env = "VERDICTAN_TEST_LANE046_LOCAL_REDIS_URL";
        std::env::remove_var(url_env);

        let mut loaded = crate::gateway::declarative_config::LoadedDeclarativeConfig::empty();
        loaded.global_rate_limit = Some(crate::gateway::rate_limit::GlobalRateLimitConfig {
            max_requests: 10,
            window_seconds: 60,
        });
        loaded.distributed_rate_limit =
            Some(crate::gateway::distributed_rate_limit::DistributedConfig {
                backend: crate::gateway::distributed_rate_limit::DistributedBackend::Redis {
                    url_env: url_env.to_string(),
                },
            });
        let config = readiness_runtime_config(false, loaded);
        let cache = Arc::new(cache::ProviderResponseCache::memory_for_test());
        let bootstrap = initialize_distributed_state_and_rollout(&config, &cache)
            .await
            .expect("LocalOnly may start without a distributed URL");
        assert_eq!(
            bootstrap.distributed_requirement,
            DistributedRequirement::LocalOnly
        );
        let state = bootstrap
            .distributed_state
            .expect("local-only state handle");
        assert!(!state.is_distributed());
        assert!(enforce_required_distributed_state_for_request(Some(state.as_ref())).is_ok());

        match previous_env {
            Some(value) => std::env::set_var("VERDICTAN_ENV", value),
            None => std::env::remove_var("VERDICTAN_ENV"),
        }
        match previous_mode {
            Some(value) => std::env::set_var("VERDICTAN_DEPLOYMENT_MODE", value),
            None => std::env::remove_var("VERDICTAN_DEPLOYMENT_MODE"),
        }
    }

    #[test]
    fn audit_wal_issues_map_to_503_reason_codes() {
        assert_eq!(
            AuditWalHealthIssue::from_snapshot(&sample_snapshot("full")),
            Some(AuditWalHealthIssue::WalFull)
        );
        assert_eq!(AuditWalHealthIssue::WalFull.reason_code(), "audit.wal_full");
        assert_eq!(
            AuditWalHealthIssue::from_snapshot(&sample_snapshot("unwritable")),
            Some(AuditWalHealthIssue::WalUnwritable)
        );
        assert_eq!(
            AuditWalHealthIssue::WalUnwritable.reason_code(),
            "audit.wal_unwritable"
        );
        assert_eq!(
            AuditWalHealthIssue::from_snapshot(&sample_snapshot("corrupt")),
            Some(AuditWalHealthIssue::CorruptCheckpoint)
        );
        assert_eq!(
            AuditWalHealthIssue::CorruptCheckpoint.reason_code(),
            "audit.wal_corrupt_checkpoint"
        );
        assert_eq!(
            AuditWalHealthIssue::from_snapshot(&sample_snapshot("quarantine")),
            Some(AuditWalHealthIssue::QuarantineNonEmpty { files: 2 })
        );
        assert_eq!(
            AuditWalHealthIssue::QuarantineNonEmpty { files: 2 }.reason_code(),
            "audit.wal_quarantine_non_empty"
        );
        assert_eq!(
            AuditWalHealthIssue::WalFull.log_and_status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            AuditWalHealthIssue::WalUnwritable.log_and_status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            AuditWalHealthIssue::CorruptCheckpoint.log_and_status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            AuditWalHealthIssue::QuarantineNonEmpty { files: 1 }.log_and_status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn evaluate_audit_wal_health_passes_when_not_required_even_if_quarantined() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let quarantine = tmp.path().join("event-retry/quarantine");
        std::fs::create_dir_all(&quarantine).expect("quarantine");
        std::fs::write(
            quarantine.join("permanent-segment-0000000000-offset-00000000000000000000.json"),
            b"{}",
        )
        .expect("quarantine file");
        let snapshot = evaluate_audit_wal_health_at(false, tmp.path()).expect("not required");
        assert!(snapshot.quarantine_non_empty);
        assert!(snapshot.wal_dir.ends_with("event-retry"));
    }

    #[test]
    fn evaluate_audit_wal_health_fails_closed_when_required_and_quarantined() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let quarantine = tmp.path().join("event-retry/quarantine");
        std::fs::create_dir_all(&quarantine).expect("quarantine");
        std::fs::write(
            quarantine.join("permanent-segment-0000000000-offset-00000000000000000000.json"),
            b"{}",
        )
        .expect("quarantine file");
        let err = evaluate_audit_wal_health_at(true, tmp.path()).expect_err("required");
        assert_eq!(err, AuditWalHealthIssue::QuarantineNonEmpty { files: 1 });
    }

    #[test]
    fn evaluate_audit_wal_health_fails_closed_on_corrupt_checkpoint_when_required() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let wal_dir = tmp.path().join("event-retry");
        std::fs::create_dir_all(&wal_dir).expect("wal dir");
        std::fs::write(wal_dir.join("checkpoint.json"), "{not-json").expect("bad checkpoint");
        let err = evaluate_audit_wal_health_at(true, tmp.path()).expect_err("required");
        assert_eq!(err, AuditWalHealthIssue::CorruptCheckpoint);
    }

    #[test]
    fn audit_metrics_json_exposes_required_fields() {
        metrics::init();
        let json = sample_snapshot("").metrics_json();
        for key in [
            "audit_wal_records",
            "audit_wal_bytes",
            "audit_wal_oldest_age_seconds",
            "audit_delivery_retries_total",
            "audit_delivery_quarantine_total",
            "audit_delivery_last_success_timestamp",
        ] {
            assert!(json.get(key).is_some(), "missing {key}");
        }
    }
}
