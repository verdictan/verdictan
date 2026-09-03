// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Gateway execution session acceptance, lifecycle management, and control-plane reporting
//! for `verdictan` gateway deployments.
//!
//! ## Responsibilities
//!
//! - **RUNNER-010**: Accept dispatched gateway execution sessions targeted at this gateway,
//!   validate the envelope (targeting + harness restriction), atomically claim
//!   the session (`pending → dispatched`), hydrate permission grants from the
//!   control plane, and set up the execution environment (working directory,
//!   env vars, timeout).
//!
//! - **RUNNER-011**: Periodic heartbeat PATCHes, checkpoint propagation,
//!   artifact registration, and event ingestion via
//!   `POST /v1/gateways/execution/sessions/{id}/events` and
//!   `POST /v1/gateways/execution/sessions/{id}/artifacts`. All calls use the gateway's
//!   own API token.
//!
//! - **RUNNER-012**: Custom harnesses are only permitted when
//!   `allows_custom_harness` is `true` on the session envelope.
//!   Attempts to supply a custom harness when the flag is `false`
//!   are rejected before execution begins, and the harness source + version are
//!   recorded in audit events when a custom harness is accepted.
//!   Harness validation delegates to [`crate::runner::harness::validate_harness`].

use std::collections::HashMap;
use std::sync::Arc;
pub use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("session {session_id} targets gateway {target:?}, but this gateway is {this:?}")]
    TargetMismatch {
        session_id: String,
        target: Option<String>,
        this: Option<String>,
    },

    #[error(
        "custom harness rejected for execution_target '{target}'; \
         only 'real_system_gateway' may use a custom harness (RUNNER-012)"
    )]
    CustomHarnessRejected { target: String },

    #[error("execution environment setup failed: {0}")]
    SetupFailed(String),

    #[error("control-plane heartbeat failed: {0}")]
    HeartbeatFailed(String),

    #[error("artifact upload failed: {0}")]
    ArtifactUploadFailed(String),

    #[error("event ingestion failed: {0}")]
    EventIngestFailed(String),

    #[error("session claim failed: {0}")]
    ClaimFailed(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

// ── Harness specification ─────────────────────────────────────────────────────

/// An optional custom harness override delivered alongside the session
/// envelope. Only accepted when `allows_custom_harness` is `true`.
///
/// When accepted the source and version are written to an audit event so the
/// control plane has a complete record of what was executed (RUNNER-012).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessSpec {
    /// Path to the harness executable or identifier of the inline script.
    pub source: String,
    /// Version tag for audit metadata (e.g. `"v1.2.3"` or a git SHA).
    pub version: String,
    /// Optional BLAKE3/SHA-256 checksum (`"<alg>:<hex>"`) for integrity
    /// verification before execution (RUNNER-012).
    pub checksum: Option<String>,
}

// ── Session envelope ──────────────────────────────────────────────────────────

/// A gateway execution session envelope delivered by the control plane.
///
/// The gateway validates targeting and harness restrictions via
/// [`RunnerSessionExecutor::validate_envelope`] before executing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerSessionEnvelope {
    /// Control-plane session UUID.
    pub session_id: String,
    /// Tenant org UUID.
    pub org_id: String,
    /// Whether this session permits custom harness overrides.
    pub allows_custom_harness: bool,
    /// Gateway ID this session is specifically targeted at.
    /// `None` means any gateway may accept it.
    pub target_gateway_id: Option<String>,
    /// Merged profile config (profile defaults + caller overrides).
    ///
    /// Recognised keys:
    /// - `command` (string) — harness command to run.
    /// - `working_dir` (string) — working directory for the harness process.
    /// - `env` (object) — extra environment variables (string → string).
    /// - `timeout_seconds` (u64) — max execution time; defaults to `3600`.
    pub profile_config: serde_json::Value,
    /// Active permission grants for the session, hydrated from the control
    /// plane's `GET /v1/gateways/execution/sessions/{id}/permissions` endpoint (RUNNER-010).
    #[serde(default)]
    pub permission_grants: Vec<crate::runner::RunnerPermissionGrant>,
    /// Optional prompt text.
    pub prompt: Option<String>,
    /// Optional custom harness override.
    /// Only permitted when `allows_custom_harness` is `true`.
    pub harness: Option<HarnessSpec>,
}

// ── Executor configuration ────────────────────────────────────────────────────

/// API connectivity configuration for [`RunnerSessionExecutor`].
#[derive(Debug, Clone)]
pub struct RunnerSessionExecutorConfig {
    /// Base URL of the Verdictan control plane (no trailing slash).
    pub api_base_url: String,
    /// Bearer token for all outbound API calls (the gateway's own API token).
    pub api_token: String,
    /// This gateway's registered ID. Used to validate `target_gateway_id`.
    pub gateway_id: Option<String>,
    /// How often to send heartbeat PATCHes while a session is running.
    pub heartbeat_interval: Duration,
}

impl RunnerSessionExecutorConfig {
    /// Build from the same environment variables used by `EventSinkConfig`.
    ///
    /// Returns `None` when `VERDICTAN_API_URL` or the API token is absent.
    ///
    /// Token precedence (mirrors `EventSinkConfig::from_env`):
    /// 1. `VERDICTAN_API_TOKEN` — unified gateway credential.
    pub fn from_env() -> Option<Self> {
        let api_base_url = std::env::var("VERDICTAN_API_URL")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty())?;

        let api_token = std::env::var("VERDICTAN_API_TOKEN")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())?;

        let gateway_id = std::env::var("VERDICTAN_GATEWAY_ID")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        Some(Self {
            api_base_url,
            api_token,
            gateway_id,
            heartbeat_interval: Duration::from_secs(30),
        })
    }
}

// ── Executor ──────────────────────────────────────────────────────────────────

/// Accepts and manages gateway execution session execution on behalf of the control plane.
///
/// Cheap to clone — all shared state lives behind an `Arc`.
#[derive(Clone, Debug)]
pub struct RunnerSessionExecutor {
    config: Arc<RunnerSessionExecutorConfig>,
    /// Pre-built HTTP client with `Authorization: Bearer <api_token>` baked in.
    client: reqwest::Client,
}

impl RunnerSessionExecutor {
    /// Create a new executor.
    ///
    /// Fails only when the API token contains bytes that cannot be used as an
    /// HTTP header value.
    pub fn new(config: RunnerSessionExecutorConfig) -> Result<Self, RunnerError> {
        let auth_value =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", config.api_token))
                .map_err(|_| {
                    RunnerError::SetupFailed("api token contains invalid header bytes".to_string())
                })?;

        let mut default_headers = reqwest::header::HeaderMap::new();
        default_headers.insert(reqwest::header::AUTHORIZATION, auth_value);

        let client = reqwest::Client::builder()
            .default_headers(default_headers)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| RunnerError::SetupFailed(format!("failed to build http client: {e}")))?;

        Ok(Self {
            config: Arc::new(config),
            client,
        })
    }

    // ── Validation ────────────────────────────────────────────────────────────

    /// Validate an inbound envelope before accepting the session.
    ///`]; custom
    /// harnesses are only allowed when `allows_custom_harness` is `true`.
    pub fn validate_envelope(&self, envelope: &RunnerSessionEnvelope) -> Result<(), RunnerError> {
        // ── Targeting check ───────────────────────────────────────────────────
        if let Some(ref target_id) = envelope.target_gateway_id {
            let target_id = target_id.trim();
            if !target_id.is_empty() {
                let matches = self
                    .config
                    .gateway_id
                    .as_deref()
                    .map(|gw| gw.trim() == target_id)
                    .unwrap_or(false);

                if !matches {
                    return Err(RunnerError::TargetMismatch {
                        session_id: envelope.session_id.clone(),
                        target: Some(target_id.to_string()),
                        this: self.config.gateway_id.clone(),
                    });
                }
            }
        }

        // ── RUNNER-012: harness restriction (canonical validation) ────────────
        match crate::runner::harness::validate_harness(
            envelope.allows_custom_harness,
            envelope.harness.is_some(),
        ) {
            Ok(()) => {}
            Err(crate::runner::HarnessValidationError::CustomHarnessRejected) => {
                return Err(RunnerError::CustomHarnessRejected {
                    target: "gateway (allows_custom_harness=false)".to_string(),
                });
            }
        }

        Ok(())
    }

    // ── Session dispatch ──────────────────────────────────────────────────────

    /// Spawn the full session lifecycle as a detached background Tokio task.
    ///
    /// Returns the `JoinHandle` so callers can await completion or cancel via
    /// `abort`. The task is best-effort; a failure is logged and the
    /// session is transitioned to `failed` on the control plane.
    pub fn spawn_session(
        &self,
        envelope: RunnerSessionEnvelope,
    ) -> tokio::task::JoinHandle<Result<(), RunnerError>> {
        let executor = self.clone();
        tokio::spawn(async move {
            let session_id = envelope.session_id.clone();
            if let Err(err) = executor.run_session(envelope).await {
                warn!(
                    session_id = %session_id,
                    error = %err,
                    "gateway execution session execution failed"
                );
                return Err(err);
            }
            Ok(())
        })
    }

    // ── Internal lifecycle ────────────────────────────────────────────────────

    async fn run_session(&self, envelope: RunnerSessionEnvelope) -> Result<(), RunnerError> {
        let session_id = &envelope.session_id;

        self.patch_session(
            session_id,
            SessionPatch {
                status: Some("running".to_string()),
                ..Default::default()
            },
        )
        .await?;

        info!(
            session_id = %session_id,
            allows_custom_harness = %envelope.allows_custom_harness,
            gateway_id = ?self.config.gateway_id,
            "gateway execution session started"
        );

        // Emit `session_started` lifecycle event (RUNNER-011).
        let _ = self
            .ingest_event(session_id, "session_started", serde_json::json!({}))
            .await;

        // RUNNER-012 audit: when a custom harness is present, emit a
        // `harness_accepted` event so the control plane has a full audit record.
        if let Some(ref harness) = envelope.harness {
            let audit = serde_json::json!({
                "harness_source":  harness.source,
                "harness_version": harness.version,
                "harness_checksum": harness.checksum,
                "allows_custom_harness": envelope.allows_custom_harness,
            });
            let _ = self
                .ingest_event(session_id, "harness_accepted", audit)
                .await;
        }

        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let hb_executor = self.clone();
        let hb_session_id = session_id.clone();
        let hb_interval = self.config.heartbeat_interval;
        let heartbeat_handle = tokio::spawn(async move {
            hb_executor
                .heartbeat_loop(hb_session_id, hb_interval, cancel_rx)
                .await;
        });

        let (final_status, error_message) = self.execute_harness(session_id, &envelope).await;

        let _ = cancel_tx.send(());
        let _ = heartbeat_handle.await;

        let _ = self
            .ingest_event(
                session_id,
                "session_finished",
                serde_json::json!({
                    "status":        final_status,
                    "error_message": error_message,
                }),
            )
            .await;

        self.patch_session(
            session_id,
            SessionPatch {
                status: Some(final_status.clone()),
                progress_pct: Some(100),
                error_message: error_message.clone(),
                ..Default::default()
            },
        )
        .await?;

        info!(
            session_id = %session_id,
            final_status = %final_status,
            "gateway execution session finished"
        );

        Ok(())
    }

    /// Execute the harness command and return `(terminal_status, error_message)`.
    ///
    /// - If `profile_config.command` (or `harness.source`) is absent the
    ///   session completes immediately with `"completed"` — useful for
    ///   informational / bookmark sessions.
    /// - The harness receives three injected environment variables so it can
    ///   self-report to the control plane:
    /// - `VERDICTAN_GATEWAY_EXECUTION_SESSION_ID`
    /// - `VERDICTAN_API_URL`
    /// - `VERDICTAN_API_TOKEN`
    async fn execute_harness(
        &self,
        session_id: &str,
        envelope: &RunnerSessionEnvelope,
    ) -> (String, Option<String>) {
        // Resolve the effective command string.
        // A custom harness `source` overrides `profile_config.command`.
        let command_str = envelope
            .harness
            .as_ref()
            .map(|h| h.source.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                envelope
                    .profile_config
                    .get("command")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
            });

        let Some(command_str) = command_str else {
            debug!(
                session_id = %session_id,
                "no harness command configured; session completes immediately"
            );
            return ("completed".to_string(), None);
        };

        // Working directory.
        let cwd = envelope
            .profile_config
            .get("working_dir")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);

        // Extra environment variables from profile config.
        let extra_env: HashMap<String, String> = envelope
            .profile_config
            .get("env")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                    .collect()
            })
            .unwrap_or_default();

        // Timeout — default 3600 s (1 hour).
        let timeout_secs = envelope
            .profile_config
            .get("timeout_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);

        // Parse command into program + args (whitespace-split; no shell expansion).
        let mut parts = command_str.split_whitespace();
        let Some(program) = parts.next() else {
            return (
                "failed".to_string(),
                Some("harness command is empty after parsing".to_string()),
            );
        };
        let args: Vec<&str> = parts.collect();

        let mut cmd = tokio::process::Command::new(program);
        cmd.args(&args);
        cmd.envs(&extra_env);

        // Inject gateway identity so the harness can self-report.
        cmd.env("VERDICTAN_GATEWAY_EXECUTION_SESSION_ID", session_id);
        cmd.env("VERDICTAN_API_URL", &self.config.api_base_url);
        cmd.env("VERDICTAN_API_TOKEN", &self.config.api_token);

        if let Some(ref dir) = cwd {
            cmd.current_dir(dir);
        }
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                warn!(
                    session_id = %session_id,
                    program = %program,
                    error = %err,
                    "runner harness failed to spawn"
                );
                return (
                    "failed".to_string(),
                    Some(format!("failed to spawn harness '{program}': {err}")),
                );
            }
        };

        match tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await {
            Ok(Ok(status)) if status.success() => {
                info!(session_id = %session_id, "runner harness exited successfully");
                ("completed".to_string(), None)
            }
            Ok(Ok(status)) => {
                let code = status.code().unwrap_or(-1);
                warn!(
                    session_id = %session_id,
                    exit_code = code,
                    "runner harness exited with non-zero status"
                );
                (
                    "failed".to_string(),
                    Some(format!("harness exited with code {code}")),
                )
            }
            Ok(Err(err)) => {
                warn!(
                    session_id = %session_id,
                    error = %err,
                    "runner harness wait error"
                );
                (
                    "failed".to_string(),
                    Some(format!("harness wait error: {err}")),
                )
            }
            Err(_elapsed) => {
                warn!(
                    session_id = %session_id,
                    timeout_secs = timeout_secs,
                    "runner harness timed out; sending kill signal"
                );
                let _ = child.kill().await;
                (
                    "timed_out".to_string(),
                    Some("harness execution timed out".to_string()),
                )
            }
        }
    }

    /// Continuous heartbeat loop (RUNNER-011).
    ///
    /// Sends an empty PATCH (which advances `last_heartbeat_at` on the control
    /// plane) on every `interval` tick until `cancel` fires.
    async fn heartbeat_loop(
        &self,
        session_id: String,
        interval: Duration,
        mut cancel: tokio::sync::oneshot::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    // Empty patch — advances last_heartbeat_at only.
                    match self.patch_session(&session_id, SessionPatch::default()).await {
                        Ok(()) => {
                            debug!(session_id = %session_id, "runner heartbeat sent");
                        }
                        Err(err) => {
                            warn!(
                                session_id = %session_id,
                                error = %err,
                                "runner heartbeat failed"
                            );
                        }
                    }
                }
                _ = &mut cancel => {
                    debug!(session_id = %session_id, "runner heartbeat loop cancelled");
                    break;
                }
            }
        }
    }

    // ── Control-plane API helpers (RUNNER-011) ────────────────────────────────

    /// PATCH `/v1/gateways/execution/sessions/{id}` — heartbeat, checkpoint, or status
    /// transition.
    pub async fn patch_session(
        &self,
        session_id: &str,
        patch: SessionPatch,
    ) -> Result<(), RunnerError> {
        let url = format!(
            "{}/v1/gateways/execution/sessions/{}",
            self.config.api_base_url, session_id
        );

        let response = self
            .client
            .patch(&url)
            .json(&patch)
            .send()
            .await
            .map_err(|e| RunnerError::HeartbeatFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(RunnerError::HeartbeatFailed(format!(
                "PATCH /v1/gateways/execution/sessions/{session_id} returned {status}: {body}"
            )));
        }

        Ok(())
    }

    /// POST `/v1/gateways/execution/sessions/{id}/events` — ingest a single event.
    pub async fn ingest_event(
        &self,
        session_id: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<(), RunnerError> {
        let url = format!(
            "{}/v1/gateways/execution/sessions/{}/events",
            self.config.api_base_url, session_id
        );

        let body = serde_json::json!({
            "event_type": event_type,
            "payload": payload,
        });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| RunnerError::EventIngestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            return Err(RunnerError::EventIngestFailed(format!(
                "POST /v1/gateways/execution/sessions/{session_id}/events returned {status}: {body_text}"
            )));
        }

        Ok(())
    }

    /// POST `/v1/gateways/execution/sessions/{id}/artifacts` — register an artifact.
    async fn upload_artifact(
        &self,
        session_id: &str,
        artifact: ArtifactUpload,
    ) -> Result<(), RunnerError> {
        if artifact.bytes.is_some() {
            return self.upload_artifact_bytes(session_id, artifact).await;
        }
        let url = format!(
            "{}/v1/gateways/execution/sessions/{}/artifacts",
            self.config.api_base_url, session_id
        );

        let response = self
            .client
            .post(&url)
            .json(&artifact)
            .send()
            .await
            .map_err(|e| RunnerError::ArtifactUploadFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(RunnerError::ArtifactUploadFailed(format!(
                "POST /v1/gateways/execution/sessions/{session_id}/artifacts returned {status}: {body}"
            )));
        }

        Ok(())
    }

    async fn upload_artifact_bytes(
        &self,
        session_id: &str,
        artifact: ArtifactUpload,
    ) -> Result<(), RunnerError> {
        let url = format!(
            "{}/v1/gateways/execution/sessions/{}/artifacts",
            self.config.api_base_url, session_id
        );
        let bytes = artifact.bytes.unwrap_or_default();
        let content_type = artifact.content_type.trim();
        let content_type = if content_type.is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };

        let mut form = reqwest::multipart::Form::new().text("name", artifact.name.clone());
        if let Some(checksum) = artifact.checksum.clone() {
            form = form.text("checksum", checksum);
        }
        form = form.part(
            "artifact",
            reqwest::multipart::Part::bytes(bytes)
                .file_name(artifact.name.clone())
                .mime_str(content_type)
                .map_err(|error| RunnerError::ArtifactUploadFailed(error.to_string()))?,
        );

        let response = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| RunnerError::ArtifactUploadFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(RunnerError::ArtifactUploadFailed(format!(
                "POST /v1/gateways/execution/sessions/{session_id}/artifacts returned {status}: {body}"
            )));
        }

        Ok(())
    }

    // ── RUNNER-010: atomic session claim ──────────────────────────────────────

    /// POST `/v1/gateways/execution/sessions/{id}/claim` — atomically claim `pending →
    /// dispatched`.
    ///
    /// Returns:
    /// - `Ok(true)` when the claim succeeds (200 OK from API).
    /// - `Ok(false)` when the session is already claimed by another gateway
    ///   (409 Conflict from API) — the caller should skip the session.
    /// - `Err(_)` on network or unexpected API errors.
    pub async fn claim_session(&self, session_id: &str) -> Result<bool, RunnerError> {
        let url = format!(
            "{}/v1/gateways/execution/sessions/{}/claim",
            self.config.api_base_url, session_id
        );

        let body = serde_json::json!({
            "gateway_id": self.config.gateway_id,
        });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| RunnerError::ClaimFailed(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            return Ok(true);
        }
        if status == reqwest::StatusCode::CONFLICT {
            // Another gateway already claimed this session — not an error.
            return Ok(false);
        }

        let body_text = response.text().await.unwrap_or_default();
        Err(RunnerError::ClaimFailed(format!(
            "POST /v1/gateways/execution/sessions/{session_id}/claim returned {status}: {body_text}"
        )))
    }

    // ── RUNNER-010: fetch permission grants ───────────────────────────────────

    /// GET `/v1/gateways/execution/sessions/{id}/permissions` — fetch active grants.
    ///
    /// Returns an empty vec on any non-critical failure rather than failing
    /// the entire session.
    pub async fn fetch_grants(
        &self,
        session_id: &str,
    ) -> Vec<crate::runner::RunnerPermissionGrant> {
        let url = format!(
            "{}/v1/gateways/execution/sessions/{}/permissions",
            self.config.api_base_url, session_id
        );

        let response = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(err) => {
                warn!(
                    session_id = %session_id,
                    error = %err,
                    "failed to fetch runner permission grants"
                );
                return vec![];
            }
        };

        if !response.status().is_success() {
            warn!(
                session_id = %session_id,
                status = %response.status(),
                "permission grants endpoint returned non-success"
            );
            return vec![];
        }

        let payload: serde_json::Value = match response.json().await {
            Ok(v) => v,
            Err(err) => {
                warn!(
                    session_id = %session_id,
                    error = %err,
                    "failed to parse permission grants response"
                );
                return vec![];
            }
        };

        payload
            .get("items")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        serde_json::from_value::<crate::runner::RunnerPermissionGrant>(item.clone())
                            .ok()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ── Data-transfer types ───────────────────────────────────────────────────────

/// Body for PATCH `/v1/gateways/execution/sessions/{id}`.
///
/// All fields are optional. An empty patch is a pure heartbeat that only
/// advances `last_heartbeat_at` on the control plane.
#[derive(Debug, Default, Serialize)]
pub struct SessionPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_pct: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Arbitrary checkpoint payload merged into `config` on the control plane.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<serde_json::Value>,
}

/// Body for POST `/v1/gateways/execution/sessions/{id}/artifacts`.
#[derive(Debug, Serialize)]
pub struct ArtifactUpload {
    pub name: String,
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    #[serde(skip_serializing)]
    pub bytes: Option<Vec<u8>>,
}

// ── Background poll loop ──────────────────────────────────────────────────────

/// Configuration for the background session poll loop.
#[derive(Debug, Clone)]
pub struct RunnerPollConfig {
    pub executor: RunnerSessionExecutor,
    /// This gateway's registered ID — used as the `target_gateway_id` filter.
    pub gateway_id: String,
    /// How often to query the control plane for new pending sessions.
    #[cfg_attr(test, allow(dead_code))]
    pub poll_interval: Duration,
}

/// Spawn a background Tokio task that polls the control plane for pending
/// sessions targeted at this gateway and executes each one.
///
/// - Polls every `config.poll_interval` (default: 10 s).
/// - Non-critical: any per-tick error is logged and the loop continues.
/// - Only accepts sessions targeted at this gateway.
#[cfg_attr(test, allow(dead_code))]
pub fn spawn_runner_poll_loop(config: RunnerPollConfig) {
    tokio::spawn(async move {
        // Brief startup delay so the first poll has a warm API connection.
        tokio::time::sleep(Duration::from_secs(5)).await;

        loop {
            if let Err(err) = poll_and_dispatch(&config).await {
                warn!(
                    gateway_id = %config.gateway_id,
                    error = %err,
                    "gateway execution session poll error"
                );
            }
            tokio::time::sleep(config.poll_interval).await;
        }
    });
}

/// One poll-and-dispatch tick: fetch pending sessions and spawn each one.
///
/// Flow (RUNNER-010):
/// 1. Fetch sessions WHERE status=pending AND execution_target=gateway AND target_gateway_id=<this_gateway>.
/// 2. Validate each session envelope (targeting + harness restriction).
/// 3. Atomically claim each session via POST /claim. If 409, another gateway beat us to it — skip.
/// 4. Hydrate permission grants from GET /permissions.
/// 5. Spawn the session execution task.
async fn poll_and_dispatch(config: &RunnerPollConfig) -> Result<(), RunnerError> {
    let mut url = reqwest::Url::parse(&format!(
        "{}/v1/gateways/execution/sessions",
        config.executor.config.api_base_url
    ))
    .map_err(|e| RunnerError::SetupFailed(format!("invalid API base URL: {e}")))?;

    {
        let mut q = url.query_pairs_mut();
        q.append_pair("execution_target", "gateway");
        q.append_pair("target_gateway_id", &config.gateway_id);
        q.append_pair("status", "pending");
        q.append_pair("limit", "10");
    }

    let response = config
        .executor
        .client
        .get(url)
        .send()
        .await
        .map_err(RunnerError::Http)?;

    let http_status = response.status();
    if !http_status.is_success() {
        let body = response.text().await.unwrap_or_default();
        warn!(
            gateway_id = %config.gateway_id,
            status = %http_status,
            body = %body,
            "runner poll returned non-success status"
        );
        // Not a hard error — the loop will retry on the next tick.
        return Ok(());
    }

    let payload: serde_json::Value = response.json().await.map_err(RunnerError::Http)?;
    let Some(items) = payload.get("items").and_then(|v| v.as_array()) else {
        return Ok(());
    };

    for item in items {
        let Some(session_id) = item
            .get("id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
        else {
            continue;
        };

        // Build a minimal envelope for validation before claiming.
        let envelope_for_validation = RunnerSessionEnvelope {
            session_id: session_id.clone(),
            org_id: item
                .get("org_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            allows_custom_harness: item
                .get("allows_custom_harness")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            target_gateway_id: item
                .get("target_gateway_id")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            profile_config: item
                .get("config")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({})),
            permission_grants: vec![],
            prompt: item
                .get("prompt")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
            // Custom harnesses are delivered via a separate signed payload,
            // not included in the polling response.
            harness: None,
        };

        if let Err(err) = config.executor.validate_envelope(&envelope_for_validation) {
            warn!(
                session_id = %session_id,
                error = %err,
                "gateway execution session envelope rejected"
            );
            continue;
        }

        // Returns false when another gateway already claimed it.
        let claimed = match config.executor.claim_session(&session_id).await {
            Ok(c) => c,
            Err(err) => {
                warn!(
                    session_id = %session_id,
                    gateway_id = %config.gateway_id,
                    error = %err,
                    "gateway execution session claim failed"
                );
                continue;
            }
        };
        if !claimed {
            debug!(
                session_id = %session_id,
                gateway_id = %config.gateway_id,
                "gateway execution session already claimed by another gateway; skipping"
            );
            continue;
        }

        let permission_grants = config.executor.fetch_grants(&session_id).await;

        // Build the complete envelope with hydrated grants.
        let envelope = RunnerSessionEnvelope {
            permission_grants,
            ..envelope_for_validation
        };

        info!(
            session_id = %session_id,
            gateway_id = %config.gateway_id,
            grants = envelope.permission_grants.len(),
            "accepting and spawning gateway execution session"
        );

        config.executor.spawn_session(envelope);
    }

    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

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
    use axum::{
        extract::{Json, Multipart, Path, Query, State},
        http::StatusCode,
        response::IntoResponse,
        routing::{get, patch, post},
        Router,
    };
    use serde_json::{json, Value};
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::sync::Notify;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CapturedArtifactUpload {
        session_id: String,
        name: String,
        content_type: String,
        checksum: Option<String>,
        bytes: Vec<u8>,
    }

    struct RunnerTestFiles {
        root: PathBuf,
    }

    impl RunnerTestFiles {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "verdictan-runner-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&root).expect("create runner test directory");
            Self { root }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root.join(name)
        }

        fn write_script(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path(name);
            fs::write(&path, contents).expect("write script");
            path
        }
    }

    impl Drop for RunnerTestFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct PatchCaptureState {
        patches: Mutex<Vec<(String, Value)>>,
        notify: Notify,
    }

    impl PatchCaptureState {
        fn new() -> Self {
            Self {
                patches: Mutex::new(Vec::new()),
                notify: Notify::new(),
            }
        }
    }

    struct LifecycleCaptureState {
        patches: Mutex<Vec<(String, Value)>>,
        events: Mutex<Vec<(String, Value)>>,
        terminal: Notify,
    }

    impl LifecycleCaptureState {
        fn new() -> Self {
            Self {
                patches: Mutex::new(Vec::new()),
                events: Mutex::new(Vec::new()),
                terminal: Notify::new(),
            }
        }
    }

    struct PollDispatchState {
        polls: Mutex<Vec<HashMap<String, String>>>,
        claims: Mutex<Vec<String>>,
        grants: Mutex<Vec<String>>,
        patches: Mutex<Vec<(String, Value)>>,
        events: Mutex<Vec<(String, Value)>>,
        terminal: Notify,
    }

    impl PollDispatchState {
        fn new() -> Self {
            Self {
                polls: Mutex::new(Vec::new()),
                claims: Mutex::new(Vec::new()),
                grants: Mutex::new(Vec::new()),
                patches: Mutex::new(Vec::new()),
                events: Mutex::new(Vec::new()),
                terminal: Notify::new(),
            }
        }
    }

    fn executor_config() -> RunnerSessionExecutorConfig {
        RunnerSessionExecutorConfig {
            api_base_url: "http://api.internal:8080".to_string(),
            api_token: "test-token".to_string(),
            gateway_id: Some("gateway-1".to_string()),
            heartbeat_interval: Duration::from_secs(30),
        }
    }

    fn sample_envelope() -> RunnerSessionEnvelope {
        RunnerSessionEnvelope {
            session_id: "session-1".to_string(),
            org_id: "org-1".to_string(),
            allows_custom_harness: true,
            target_gateway_id: Some("gateway-1".to_string()),
            profile_config: json!({}),
            permission_grants: Vec::new(),
            prompt: Some("hello".to_string()),
            harness: None,
        }
    }

    async fn capture_artifact_upload(
        Path(session_id): Path<String>,
        State(captured): State<Arc<Mutex<Vec<CapturedArtifactUpload>>>>,
        mut multipart: Multipart,
    ) -> StatusCode {
        let mut name: Option<String> = None;
        let mut checksum: Option<String> = None;
        let mut content_type: Option<String> = None;
        let mut bytes: Option<Vec<u8>> = None;

        while let Some(field) = multipart.next_field().await.expect("next field") {
            match field.name().unwrap_or_default() {
                "name" => name = Some(field.text().await.expect("name")),
                "checksum" => checksum = Some(field.text().await.expect("checksum")),
                "artifact" => {
                    if content_type.is_none() {
                        content_type = field.content_type().map(str::to_string);
                    }
                    bytes = Some(field.bytes().await.expect("artifact bytes").to_vec());
                }
                _ => {}
            }
        }

        captured
            .lock()
            .expect("captured uploads")
            .push(CapturedArtifactUpload {
                session_id,
                name: name.expect("artifact name"),
                content_type: content_type
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                checksum,
                bytes: bytes.expect("artifact bytes"),
            });

        StatusCode::CREATED
    }

    async fn reject_patch(
        Path(session_id): Path<String>,
        Json(payload): Json<Value>,
    ) -> impl axum::response::IntoResponse {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "session_id": session_id,
                "received": payload,
                "error": "boom"
            })),
        )
    }

    async fn capture_json_artifact(
        Path(session_id): Path<String>,
        State(captured): State<Arc<Mutex<Vec<(String, Value)>>>>,
        Json(payload): Json<Value>,
    ) -> StatusCode {
        captured
            .lock()
            .expect("captured artifact json")
            .push((session_id, payload));
        StatusCode::CREATED
    }

    async fn claim_handler(Path(session_id): Path<String>) -> impl IntoResponse {
        match session_id.as_str() {
            "claimed" => StatusCode::OK.into_response(),
            "conflict" => StatusCode::CONFLICT.into_response(),
            _ => (StatusCode::BAD_GATEWAY, "claim failed").into_response(),
        }
    }

    async fn reject_event(
        Path(session_id): Path<String>,
        Json(payload): Json<Value>,
    ) -> impl axum::response::IntoResponse {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "session_id": session_id,
                "received": payload,
                "error": "event boom"
            })),
        )
    }

    async fn capture_patch(
        Path(session_id): Path<String>,
        State(captured): State<Arc<PatchCaptureState>>,
        Json(payload): Json<Value>,
    ) -> StatusCode {
        captured
            .patches
            .lock()
            .expect("captured heartbeat patches")
            .push((session_id, payload));
        captured.notify.notify_one();
        StatusCode::OK
    }

    async fn capture_lifecycle_patch(
        Path(session_id): Path<String>,
        State(captured): State<Arc<LifecycleCaptureState>>,
        Json(payload): Json<Value>,
    ) -> StatusCode {
        let terminal = payload
            .get("status")
            .and_then(|value| value.as_str())
            .is_some_and(|status| matches!(status, "completed" | "failed" | "timed_out"));
        captured
            .patches
            .lock()
            .expect("captured lifecycle patches")
            .push((session_id, payload));
        if terminal {
            captured.terminal.notify_one();
        }
        StatusCode::OK
    }

    async fn capture_lifecycle_event(
        Path(session_id): Path<String>,
        State(captured): State<Arc<LifecycleCaptureState>>,
        Json(payload): Json<Value>,
    ) -> StatusCode {
        captured
            .events
            .lock()
            .expect("captured lifecycle events")
            .push((session_id, payload));
        StatusCode::CREATED
    }

    async fn poll_sessions_handler(
        Query(query): Query<HashMap<String, String>>,
        State(captured): State<Arc<PollDispatchState>>,
    ) -> Json<Value> {
        captured
            .polls
            .lock()
            .expect("captured poll queries")
            .push(query);

        Json(json!({
            "items": [
                {
                    "org_id": "org-missing-id",
                    "target_gateway_id": "gateway-1",
                    "config": {}
                },
                {
                    "id": "wrong-target",
                    "org_id": "org-wrong-target",
                    "target_gateway_id": "gateway-2",
                    "config": {}
                },
                {
                    "id": "claim-error",
                    "org_id": "org-claim-error",
                    "target_gateway_id": "gateway-1",
                    "config": {}
                },
                {
                    "id": "conflict",
                    "org_id": "org-conflict",
                    "target_gateway_id": "gateway-1",
                    "config": {}
                },
                {
                    "id": "accepted",
                    "org_id": "org-accepted",
                    "target_gateway_id": "gateway-1",
                    "config": {},
                    "prompt": "run now"
                }
            ]
        }))
    }

    async fn poll_sessions_missing_items_handler() -> Json<Value> {
        Json(json!({
            "next_cursor": null
        }))
    }

    async fn poll_sessions_error_handler() -> impl IntoResponse {
        (StatusCode::BAD_GATEWAY, "poll boom")
    }

    async fn capture_poll_patch(
        Path(session_id): Path<String>,
        State(captured): State<Arc<PollDispatchState>>,
        Json(payload): Json<Value>,
    ) -> StatusCode {
        let terminal = payload
            .get("status")
            .and_then(|value| value.as_str())
            .is_some_and(|status| status == "completed");
        captured
            .patches
            .lock()
            .expect("captured poll patches")
            .push((session_id, payload));
        if terminal {
            captured.terminal.notify_one();
        }
        StatusCode::OK
    }

    async fn capture_poll_event(
        Path(session_id): Path<String>,
        State(captured): State<Arc<PollDispatchState>>,
        Json(payload): Json<Value>,
    ) -> StatusCode {
        captured
            .events
            .lock()
            .expect("captured poll events")
            .push((session_id, payload));
        StatusCode::CREATED
    }

    async fn poll_claim_handler(
        Path(session_id): Path<String>,
        State(captured): State<Arc<PollDispatchState>>,
    ) -> impl IntoResponse {
        captured
            .claims
            .lock()
            .expect("captured claims")
            .push(session_id.clone());
        match session_id.as_str() {
            "accepted" => StatusCode::OK.into_response(),
            "conflict" => StatusCode::CONFLICT.into_response(),
            "claim-error" => (StatusCode::BAD_GATEWAY, "claim boom").into_response(),
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }

    async fn poll_grants_handler(
        Path(session_id): Path<String>,
        State(captured): State<Arc<PollDispatchState>>,
    ) -> impl IntoResponse {
        captured
            .grants
            .lock()
            .expect("captured grants")
            .push(session_id.clone());
        Json(json!({
            "items": [
                {
                    "id": format!("{session_id}-grant"),
                    "grant_type": "tool",
                    "scope": { "tool_names": ["bash"] },
                    "expires_at": null
                }
            ]
        }))
        .into_response()
    }

    async fn grants_handler(Path(session_id): Path<String>) -> impl axum::response::IntoResponse {
        match session_id.as_str() {
            "valid" => Json(json!({
                "items": [
                    {
                        "id": "grant-1",
                        "grant_type": "tool",
                        "scope": { "tool_names": ["bash"] },
                        "expires_at": null
                    },
                    {
                        "id": "invalid",
                        "grant_type": 5
                    }
                ]
            }))
            .into_response(),
            "invalid-json" => (StatusCode::OK, "not-json").into_response(),
            _ => StatusCode::BAD_GATEWAY.into_response(),
        }
    }

    async fn start_test_server(app: Router) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("server addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test server");
        });
        addr
    }

    #[test]
    fn config_from_env_requires_and_trims_values() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        crate::test_support::unset_var("VERDICTAN_API_URL");
        crate::test_support::unset_var("VERDICTAN_API_TOKEN");
        crate::test_support::unset_var("VERDICTAN_GATEWAY_ID");
        assert!(RunnerSessionExecutorConfig::from_env().is_none());

        crate::test_support::set_var("VERDICTAN_API_URL", "https://api.verdictan.com/ ");
        crate::test_support::set_var("VERDICTAN_API_TOKEN", "  token-123  ");
        crate::test_support::set_var("VERDICTAN_GATEWAY_ID", "  gateway-a  ");

        let config = RunnerSessionExecutorConfig::from_env().expect("config from env");
        assert_eq!(config.api_base_url, "https://api.verdictan.com");
        assert_eq!(config.api_token, "token-123");
        assert_eq!(config.gateway_id.as_deref(), Some("gateway-a"));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));

        crate::test_support::unset_var("VERDICTAN_API_URL");
        crate::test_support::unset_var("VERDICTAN_API_TOKEN");
        crate::test_support::unset_var("VERDICTAN_GATEWAY_ID");
    }

    #[test]
    fn config_from_env_rejects_blank_values() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        crate::test_support::set_var("VERDICTAN_API_URL", "   ");
        crate::test_support::set_var("VERDICTAN_API_TOKEN", "token");
        crate::test_support::set_var("VERDICTAN_GATEWAY_ID", "   ");
        assert!(RunnerSessionExecutorConfig::from_env().is_none());

        crate::test_support::set_var("VERDICTAN_API_URL", "https://api.verdictan.com");
        crate::test_support::set_var("VERDICTAN_API_TOKEN", "   ");
        assert!(RunnerSessionExecutorConfig::from_env().is_none());

        crate::test_support::unset_var("VERDICTAN_API_URL");
        crate::test_support::unset_var("VERDICTAN_API_TOKEN");
        crate::test_support::unset_var("VERDICTAN_GATEWAY_ID");
    }

    #[test]
    fn new_rejects_invalid_authorization_header_values() {
        let mut config = executor_config();
        config.api_token = "bad\nvalue".to_string();

        let error = RunnerSessionExecutor::new(config).expect_err("invalid token");
        match error {
            RunnerError::SetupFailed(message) => {
                assert!(message.contains("invalid header bytes"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn validate_envelope_checks_targeting_and_harness_rules() {
        let executor = RunnerSessionExecutor::new(executor_config()).expect("executor");

        let mut envelope = sample_envelope();
        envelope.target_gateway_id = Some(" gateway-1 ".to_string());
        assert!(executor.validate_envelope(&envelope).is_ok());

        envelope.target_gateway_id = Some("gateway-2".to_string());
        match executor.validate_envelope(&envelope).expect_err("mismatch") {
            RunnerError::TargetMismatch {
                session_id,
                target,
                this,
            } => {
                assert_eq!(session_id, "session-1");
                assert_eq!(target.as_deref(), Some("gateway-2"));
                assert_eq!(this.as_deref(), Some("gateway-1"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }

        let mut harness_rejected = sample_envelope();
        harness_rejected.allows_custom_harness = false;
        harness_rejected.harness = Some(HarnessSpec {
            source: "/tmp/custom-harness".to_string(),
            version: "v1".to_string(),
            checksum: Some("sha256:abc".to_string()),
        });
        match executor
            .validate_envelope(&harness_rejected)
            .expect_err("custom harness should be rejected")
        {
            RunnerError::CustomHarnessRejected { target } => {
                assert!(target.contains("allows_custom_harness=false"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_harness_completes_without_a_command() {
        let executor = RunnerSessionExecutor::new(executor_config()).expect("executor");
        let result = executor
            .execute_harness("session-1", &sample_envelope())
            .await;
        assert_eq!(result, ("completed".to_string(), None));
    }

    #[tokio::test]
    async fn execute_harness_reports_spawn_failures() {
        let executor = RunnerSessionExecutor::new(executor_config()).expect("executor");
        let mut envelope = sample_envelope();
        envelope.profile_config = json!({
            "command": "verdictan-command-that-should-not-exist-anywhere"
        });

        let (status, error) = executor.execute_harness("session-1", &envelope).await;
        assert_eq!(status, "failed");
        assert!(
            error
                .as_deref()
                .is_some_and(|message| message.contains("failed to spawn harness")),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn artifact_upload_with_bytes_posts_multipart() {
        let captured = Arc::new(Mutex::new(Vec::<CapturedArtifactUpload>::new()));
        let app = Router::new()
            .route(
                "/v1/gateways/execution/sessions/:id/artifacts",
                post(capture_artifact_upload),
            )
            .with_state(Arc::clone(&captured));
        let addr = start_test_server(app).await;

        let mut config = executor_config();
        config.api_base_url = format!("http://{addr}");
        let executor = RunnerSessionExecutor::new(config).expect("executor");

        executor
            .upload_artifact(
                "session-42",
                ArtifactUpload {
                    name: "stdout.log".to_string(),
                    content_type: "text/plain".to_string(),
                    size_bytes: Some(5),
                    storage_path: None,
                    checksum: Some("sha256:test".to_string()),
                    bytes: Some(b"hello".to_vec()),
                },
            )
            .await
            .expect("artifact upload");

        let uploads = captured.lock().expect("captured uploads");
        assert_eq!(
            uploads.as_slice(),
            &[CapturedArtifactUpload {
                session_id: "session-42".to_string(),
                name: "stdout.log".to_string(),
                content_type: "text/plain".to_string(),
                checksum: Some("sha256:test".to_string()),
                bytes: b"hello".to_vec(),
            }]
        );
    }

    #[tokio::test]
    async fn upload_artifact_without_bytes_posts_json_body() {
        let captured = Arc::new(Mutex::new(Vec::<(String, Value)>::new()));
        let app = Router::new()
            .route(
                "/v1/gateways/execution/sessions/:id/artifacts",
                post(capture_json_artifact),
            )
            .with_state(Arc::clone(&captured));
        let addr = start_test_server(app).await;

        let mut config = executor_config();
        config.api_base_url = format!("http://{addr}");
        let executor = RunnerSessionExecutor::new(config).expect("executor");

        executor
            .upload_artifact(
                "session-99",
                ArtifactUpload {
                    name: "summary.json".to_string(),
                    content_type: "application/json".to_string(),
                    size_bytes: Some(12),
                    storage_path: Some("artifacts/summary.json".to_string()),
                    checksum: Some("sha256:abcd".to_string()),
                    bytes: None,
                },
            )
            .await
            .expect("artifact upload");

        let captured = captured.lock().expect("captured artifact json");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].0, "session-99");
        assert_eq!(captured[0].1["name"], "summary.json");
        assert_eq!(captured[0].1["content_type"], "application/json");
        assert_eq!(captured[0].1["storage_path"], "artifacts/summary.json");
        assert!(captured[0].1.get("bytes").is_none());
    }

    #[tokio::test]
    async fn upload_artifact_bytes_defaults_content_type_and_rejects_invalid_mime() {
        let captured = Arc::new(Mutex::new(Vec::<CapturedArtifactUpload>::new()));
        let app = Router::new()
            .route(
                "/v1/gateways/execution/sessions/:id/artifacts",
                post(capture_artifact_upload),
            )
            .with_state(Arc::clone(&captured));
        let addr = start_test_server(app).await;

        let mut config = executor_config();
        config.api_base_url = format!("http://{addr}");
        let executor = RunnerSessionExecutor::new(config).expect("executor");

        executor
            .upload_artifact(
                "session-default",
                ArtifactUpload {
                    name: "blob.bin".to_string(),
                    content_type: "   ".to_string(),
                    size_bytes: None,
                    storage_path: None,
                    checksum: None,
                    bytes: Some(vec![1, 2, 3]),
                },
            )
            .await
            .expect("default content type upload");

        let uploads = captured.lock().expect("captured uploads");
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].session_id, "session-default");
        assert_eq!(uploads[0].content_type, "application/octet-stream");
        assert_eq!(uploads[0].checksum, None);
        drop(uploads);

        let error = executor
            .upload_artifact(
                "session-invalid",
                ArtifactUpload {
                    name: "broken.bin".to_string(),
                    content_type: "not a mime".to_string(),
                    size_bytes: None,
                    storage_path: None,
                    checksum: None,
                    bytes: Some(vec![9]),
                },
            )
            .await
            .expect_err("invalid mime");

        match error {
            RunnerError::ArtifactUploadFailed(message) => {
                assert!(!message.is_empty());
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn patch_session_surfaces_non_success_statuses() {
        let app = Router::new().route("/v1/gateways/execution/sessions/:id", patch(reject_patch));
        let addr = start_test_server(app).await;

        let mut config = executor_config();
        config.api_base_url = format!("http://{addr}");
        let executor = RunnerSessionExecutor::new(config).expect("executor");

        let error = executor
            .patch_session(
                "session-500",
                SessionPatch {
                    status: Some("running".to_string()),
                    progress_pct: Some(10),
                    error_message: None,
                    checkpoint: Some(json!({ "step": "claim" })),
                },
            )
            .await
            .expect_err("patch should fail");

        match error {
            RunnerError::HeartbeatFailed(message) => {
                assert!(message.contains("session-500"));
                assert!(message.contains("500"));
                assert!(message.contains("boom"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn ingest_event_surfaces_non_success_statuses() {
        let app = Router::new().route(
            "/v1/gateways/execution/sessions/:id/events",
            post(reject_event),
        );
        let addr = start_test_server(app).await;

        let mut config = executor_config();
        config.api_base_url = format!("http://{addr}");
        let executor = RunnerSessionExecutor::new(config).expect("executor");

        let error = executor
            .ingest_event("session-500", "checkpoint", json!({ "step": "run" }))
            .await
            .expect_err("event ingestion should fail");

        match error {
            RunnerError::EventIngestFailed(message) => {
                assert!(message.contains("session-500"));
                assert!(message.contains("502"));
                assert!(message.contains("event boom"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn claim_session_maps_success_conflict_and_error_statuses() {
        let app = Router::new().route(
            "/v1/gateways/execution/sessions/:id/claim",
            post(claim_handler),
        );
        let addr = start_test_server(app).await;

        let mut config = executor_config();
        config.api_base_url = format!("http://{addr}");
        let executor = RunnerSessionExecutor::new(config).expect("executor");

        assert!(executor.claim_session("claimed").await.expect("claimed"));
        assert!(!executor.claim_session("conflict").await.expect("conflict"));

        let error = executor
            .claim_session("broken")
            .await
            .expect_err("claim error");
        match error {
            RunnerError::ClaimFailed(message) => {
                assert!(message.contains("broken"));
                assert!(message.contains("claim failed"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_grants_parses_valid_items_and_returns_empty_on_failures() {
        let app = Router::new().route(
            "/v1/gateways/execution/sessions/:id/permissions",
            get(grants_handler),
        );
        let addr = start_test_server(app).await;

        let mut config = executor_config();
        config.api_base_url = format!("http://{addr}");
        let executor = RunnerSessionExecutor::new(config).expect("executor");

        let grants = executor.fetch_grants("valid").await;
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].id, "grant-1");
        assert_eq!(grants[0].grant_type, "tool");
        assert_eq!(grants[0].scope["tool_names"][0], "bash");

        assert!(executor.fetch_grants("invalid-json").await.is_empty());
        assert!(executor.fetch_grants("error").await.is_empty());
    }

    #[tokio::test]
    async fn poll_and_dispatch_rejects_invalid_api_base_urls() {
        let mut config = executor_config();
        config.api_base_url = "not a url".to_string();
        let executor = RunnerSessionExecutor::new(config).expect("executor");

        let error = poll_and_dispatch(&RunnerPollConfig {
            executor,
            gateway_id: "gateway-1".to_string(),
            poll_interval: Duration::from_secs(10),
        })
        .await
        .expect_err("invalid url should fail");

        match error {
            RunnerError::SetupFailed(message) => {
                assert!(message.contains("invalid API base URL"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn poll_and_dispatch_ignores_non_success_and_missing_items_responses() {
        let error_addr = start_test_server(Router::new().route(
            "/v1/gateways/execution/sessions",
            get(poll_sessions_error_handler),
        ))
        .await;
        let missing_addr = start_test_server(Router::new().route(
            "/v1/gateways/execution/sessions",
            get(poll_sessions_missing_items_handler),
        ))
        .await;

        let mut error_config = executor_config();
        error_config.api_base_url = format!("http://{error_addr}");
        let error_executor = RunnerSessionExecutor::new(error_config).expect("executor");
        poll_and_dispatch(&RunnerPollConfig {
            executor: error_executor,
            gateway_id: "gateway-1".to_string(),
            poll_interval: Duration::from_secs(10),
        })
        .await
        .expect("non-success poll response should be ignored");

        let mut missing_config = executor_config();
        missing_config.api_base_url = format!("http://{missing_addr}");
        let missing_executor = RunnerSessionExecutor::new(missing_config).expect("executor");
        poll_and_dispatch(&RunnerPollConfig {
            executor: missing_executor,
            gateway_id: "gateway-1".to_string(),
            poll_interval: Duration::from_secs(10),
        })
        .await
        .expect("missing items should be ignored");
    }

    #[test]
    fn runner_error_target_mismatch_display() {
        let err = RunnerError::TargetMismatch {
            session_id: "sess-1".to_string(),
            target: Some("gw-target".to_string()),
            this: Some("gw-local".to_string()),
        };
        let msg = err.to_string();
        assert!(msg.contains("sess-1"));
        assert!(msg.contains("gw-target"));
        assert!(msg.contains("gw-local"));
    }

    #[test]
    fn runner_error_custom_harness_rejected_display() {
        let err = RunnerError::CustomHarnessRejected {
            target: "sandbox_gateway".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("sandbox_gateway"));
        assert!(msg.contains("RUNNER-012"));
    }

    #[test]
    fn runner_error_setup_failed_display() {
        let err = RunnerError::SetupFailed("missing env var".to_string());
        assert!(err.to_string().contains("missing env var"));
    }

    #[test]
    fn runner_error_heartbeat_failed_display() {
        let err = RunnerError::HeartbeatFailed("timeout".to_string());
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn runner_error_artifact_upload_failed_display() {
        let err = RunnerError::ArtifactUploadFailed("network error".to_string());
        assert!(err.to_string().contains("network error"));
    }

    #[test]
    fn runner_error_event_ingest_failed_display() {
        let err = RunnerError::EventIngestFailed("server 500".to_string());
        assert!(err.to_string().contains("server 500"));
    }

    #[test]
    fn runner_error_claim_failed_display() {
        let err = RunnerError::ClaimFailed("already claimed".to_string());
        assert!(err.to_string().contains("already claimed"));
    }

    // ── HarnessSpec ─────────────────────────────────────────────────────

    #[test]
    fn harness_spec_serde_round_trip() {
        let spec = HarnessSpec {
            source: "/usr/local/bin/custom-harness".to_string(),
            version: "v1.2.3".to_string(),
            checksum: Some("sha256:abc123".to_string()),
        };
        let j = serde_json::to_string(&spec).unwrap();
        let deserialized: HarnessSpec = serde_json::from_str(&j).unwrap();
        assert_eq!(deserialized.source, "/usr/local/bin/custom-harness");
        assert_eq!(deserialized.version, "v1.2.3");
        assert_eq!(deserialized.checksum, Some("sha256:abc123".to_string()));
    }

    #[test]
    fn harness_spec_no_checksum() {
        let spec = HarnessSpec {
            source: "harness.sh".to_string(),
            version: "1.0".to_string(),
            checksum: None,
        };
        let j = serde_json::to_value(&spec).unwrap();
        assert_eq!(j["source"], "harness.sh");
        assert!(j["checksum"].is_null());
    }

    // ── RunnerSessionEnvelope ───────────────────────────────────────────

    #[test]
    fn runner_session_envelope_serde() {
        let envelope = RunnerSessionEnvelope {
            session_id: "sess-uuid".to_string(),
            org_id: "org-uuid".to_string(),
            allows_custom_harness: false,
            target_gateway_id: Some("gw-1".to_string()),
            profile_config: serde_json::json!({
                "command": "node runner.js",
                "timeout_seconds": 300
            }),
            harness: None,
            prompt: None,
            permission_grants: vec![],
        };
        let j = serde_json::to_string(&envelope).unwrap();
        let deserialized: RunnerSessionEnvelope = serde_json::from_str(&j).unwrap();
        assert_eq!(deserialized.session_id, "sess-uuid");
        assert!(!deserialized.allows_custom_harness);
    }
}
