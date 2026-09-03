// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use chrono::{DateTime, Utc};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::persistence::sha256_hex;

use super::{
    bounded_child::{clamp_timeout, BoundedChildPool},
    declarative_config::HostedGatewayLocalAccessConfig,
    shell_actions::{classify_shell_command, ShellRiskLevel},
};

/// PERF-014 work-reuse / local-access verifier concurrency (matches
/// [`crate::gateway::bounded_child::BoundedChildConfig`] process capacity).
const READER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_APPROVAL_GRANTS: usize = 4_096;

fn verifier_child_pool() -> &'static BoundedChildPool {
    BoundedChildPool::global()
}

#[derive(Clone, Debug)]
pub struct LocalAccessRequest {
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCommandApprovalGrant {
    pub id: String,
    pub command_digest_sha256: String,
    pub working_directory: String,
    pub risk_level: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Default)]
struct ApprovalGrantState {
    pending: HashMap<String, LocalCommandApprovalGrant>,
    consumed: HashMap<String, DateTime<Utc>>,
}

#[derive(Clone, Default)]
pub struct LocalCommandApprovalStore {
    state: Arc<Mutex<ApprovalGrantState>>,
}

impl std::fmt::Debug for LocalCommandApprovalStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalCommandApprovalStore")
            .finish_non_exhaustive()
    }
}

impl LocalCommandApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a grant already authorized by the owning control-plane flow.
    ///
    /// This store does not mint approvals. Callers must register only grants
    /// obtained through an authenticated, authoritative approval channel.
    pub async fn register_authoritative(
        &self,
        mut grant: LocalCommandApprovalGrant,
    ) -> Result<(), LocalCommandError> {
        grant.id = grant.id.trim().to_string();
        grant.command_digest_sha256 = grant.command_digest_sha256.trim().to_ascii_lowercase();
        grant.working_directory = grant.working_directory.trim().to_string();
        grant.risk_level = normalize_risk_level(&grant.risk_level)?
            .as_str()
            .to_string();
        if grant.id.is_empty()
            || grant.working_directory.is_empty()
            || !is_sha256_hex(&grant.command_digest_sha256)
        {
            return Err(LocalCommandError::InvalidApprovalGrant);
        }
        let now = Utc::now();
        if grant.expires_at <= now {
            return Err(LocalCommandError::ApprovalExpired);
        }

        let mut state = self.state.lock().await;
        prune_consumed_grants(&mut state, now);
        if state.pending.len().saturating_add(state.consumed.len()) >= MAX_APPROVAL_GRANTS {
            return Err(LocalCommandError::ApprovalCapacity);
        }
        if state.pending.contains_key(&grant.id) || state.consumed.contains_key(&grant.id) {
            return Err(LocalCommandError::ApprovalReplay);
        }
        state.pending.insert(grant.id.clone(), grant);
        Ok(())
    }

    async fn consume_matching(
        &self,
        grant_id: &str,
        command_digest_sha256: &str,
        working_directory: &Path,
        risk_level: NormalizedRiskLevel,
    ) -> Result<String, LocalCommandError> {
        let grant_id = grant_id.trim();
        if grant_id.is_empty() {
            return Err(LocalCommandError::ApprovalRequired);
        }

        let now = Utc::now();
        let mut state = self.state.lock().await;
        prune_consumed_grants(&mut state, now);
        if state.consumed.contains_key(grant_id) {
            return Err(LocalCommandError::ApprovalReplay);
        }
        let grant = state
            .pending
            .remove(grant_id)
            .ok_or(LocalCommandError::ApprovalUnavailable)?;
        if grant.expires_at <= now {
            return Err(LocalCommandError::ApprovalExpired);
        }
        let grant_risk = normalize_risk_level(&grant.risk_level)?;
        if grant.command_digest_sha256 != command_digest_sha256
            || Path::new(&grant.working_directory) != working_directory
            || grant_risk != risk_level
        {
            return Err(LocalCommandError::ApprovalMismatch);
        }
        state.consumed.insert(grant.id.clone(), grant.expires_at);
        Ok(grant.id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum NormalizedRiskLevel {
    Safe,
    Moderate,
    High,
    Critical,
}

impl NormalizedRiskLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Moderate => "moderate",
            Self::High => "destructive",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LocalCommandError {
    #[error("local verifier capacity exhausted")]
    CapacityExceeded,
    #[error("command requires an authoritative approval grant")]
    ApprovalRequired,
    #[error("approval grant is unavailable")]
    ApprovalUnavailable,
    #[error("approval grant has expired")]
    ApprovalExpired,
    #[error("approval grant has already been consumed")]
    ApprovalReplay,
    #[error("approval grant does not match command, working directory, or risk")]
    ApprovalMismatch,
    #[error("approval grant is malformed")]
    InvalidApprovalGrant,
    #[error("approval grant store is at capacity")]
    ApprovalCapacity,
    #[error("unknown local command risk classification: {0}")]
    UnknownRiskClassification(String),
    #[error("{0}")]
    PolicyDenied(String),
    #[error("local command execution failed: {0}")]
    Execution(#[from] std::io::Error),
    #[error("local command output reader failed: {0}")]
    OutputReader(String),
}

impl LocalCommandError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::CapacityExceeded => 429,
            Self::ApprovalRequired
            | Self::ApprovalUnavailable
            | Self::ApprovalExpired
            | Self::ApprovalReplay
            | Self::ApprovalMismatch
            | Self::InvalidApprovalGrant
            | Self::UnknownRiskClassification(_)
            | Self::PolicyDenied(_) => 403,
            Self::ApprovalCapacity => 503,
            Self::Execution(_) | Self::OutputReader(_) => 500,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LocalFileSummary {
    pub path: String,
    pub size_bytes: u64,
    pub audit: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LocalDirectoryEntry {
    pub name: String,
    pub path: String,
    pub relative_path: String,
    pub entry_type: String,
    pub size_bytes: Option<u64>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LocalDirectoryListing {
    pub path: String,
    pub entries: Vec<LocalDirectoryEntry>,
    pub audit: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LocalTextFileRead {
    pub path: String,
    pub relative_path: String,
    pub size_bytes: u64,
    pub content: String,
    pub audit: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LocalPathStat {
    pub path: String,
    pub relative_path: String,
    pub entry_type: String,
    pub size_bytes: Option<u64>,
    pub audit: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LocalPathDeletion {
    pub path: String,
    pub relative_path: String,
    pub entry_type: String,
    pub audit: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LocalTextFileWrite {
    pub path: String,
    pub relative_path: String,
    pub bytes_written: u64,
    pub created: bool,
    pub audit: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LocalDirectoryCreation {
    pub path: String,
    pub relative_path: String,
    pub already_existed: bool,
    pub audit: serde_json::Value,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LocalShellExecution {
    pub command: String,
    pub argv: Vec<String>,
    pub working_directory: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub risk_level: String,
    pub audit: serde_json::Value,
}

#[derive(Clone, Debug)]
struct BoundedOutput {
    bytes: Vec<u8>,
    total_bytes: u64,
    truncated: bool,
}

#[derive(Debug)]
struct BoundedCommandOutcome {
    stdout: BoundedOutput,
    stderr: BoundedOutput,
    exit_code: Option<i32>,
    timed_out: bool,
    output_limit_stream: Option<&'static str>,
}

pub async fn validate_path(
    config: &HostedGatewayLocalAccessConfig,
    path: &Path,
) -> anyhow::Result<PathBuf> {
    if !config.enabled {
        return Err(anyhow!("hosted gateway local access is disabled"));
    }
    let canonical = tokio::fs::canonicalize(path)
        .await
        .with_context(|| format!("failed to resolve {}", path.display()))?;
    matched_allowed_root(config, &canonical)?;
    if path_is_excluded(config, &canonical) {
        return Err(anyhow!(
            "path is excluded by hosted gateway local access policy"
        ));
    }

    // CLI-SEC-008 / CLI-SEC-004: After canonicalization, reject paths that are
    // themselves symlinks to mitigate TOCTOU races where a symlink is swapped
    // between validation and use.
    // NOTE: `O_NOFOLLOW` should be used at open-time for full production hardening.
    let meta = tokio::fs::symlink_metadata(&canonical)
        .await
        .with_context(|| format!("failed to read metadata for {}", canonical.display()))?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "path {} resolves to a symlink, which is rejected by security policy",
            canonical.display()
        ));
    }

    Ok(canonical)
}

pub async fn read_file_summary(
    config: &HostedGatewayLocalAccessConfig,
    request: &LocalAccessRequest,
) -> anyhow::Result<LocalFileSummary> {
    let path = validate_path(config, &request.path).await?;
    let metadata = tokio::fs::metadata(&path).await?;
    if metadata.len() > config.max_file_bytes {
        return Err(anyhow!("file exceeds hosted gateway max_file_bytes"));
    }
    Ok(LocalFileSummary {
        path: path.display().to_string(),
        size_bytes: metadata.len(),
        audit: serde_json::json!({
            "operation": "read_file_summary",
            "path": path.display().to_string(),
            "size_bytes": metadata.len(),
        }),
    })
}

pub async fn list_directory(
    config: &HostedGatewayLocalAccessConfig,
    request: &LocalAccessRequest,
) -> anyhow::Result<LocalDirectoryListing> {
    let path = validate_path(config, &request.path).await?;
    let metadata = tokio::fs::metadata(&path).await?;
    if !metadata.is_dir() {
        return Err(anyhow!("path is not a directory"));
    }

    let allowed_root = matched_allowed_root(config, &path)?;
    let mut entries = Vec::new();
    let mut skipped_entries = 0_u64;

    let mut dir = tokio::fs::read_dir(&path).await?;
    while let Some(entry) = dir.next_entry().await? {
        let entry_path = entry.path();
        let canonical_entry = match tokio::fs::canonicalize(&entry_path).await {
            Ok(value) => value,
            Err(_) => {
                skipped_entries += 1;
                continue;
            }
        };

        if matched_allowed_root(config, &canonical_entry).is_err()
            || path_is_excluded(config, &canonical_entry)
        {
            skipped_entries += 1;
            continue;
        }

        let entry_metadata = tokio::fs::metadata(&canonical_entry).await?;
        entries.push(LocalDirectoryEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            path: canonical_entry.display().to_string(),
            relative_path: relative_path(&allowed_root, &canonical_entry),
            entry_type: entry_type(&entry_metadata),
            size_bytes: entry_metadata.is_file().then_some(entry_metadata.len()),
        });
    }

    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let entries_digest = sha256_hex(&serde_json::to_vec(&entries)?);

    Ok(LocalDirectoryListing {
        path: path.display().to_string(),
        entries,
        audit: serde_json::json!({
            "operation": "list_directory",
            "path": path.display().to_string(),
            "skipped_entries": skipped_entries,
            "entries_digest_sha256": entries_digest,
        }),
    })
}

pub async fn read_text_file(
    config: &HostedGatewayLocalAccessConfig,
    request: &LocalAccessRequest,
) -> anyhow::Result<LocalTextFileRead> {
    let path = validate_path(config, &request.path).await?;
    let metadata = tokio::fs::metadata(&path).await?;
    if !metadata.is_file() {
        return Err(anyhow!("path is not a file"));
    }
    if metadata.len() > config.max_file_bytes {
        return Err(anyhow!("file exceeds hosted gateway max_file_bytes"));
    }

    let bytes = tokio::fs::read(&path).await?;
    if bytes.contains(&0) {
        return Err(anyhow!("file appears to be binary"));
    }
    let content = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow!("file is not valid UTF-8 text"))?
        .to_string();
    let allowed_root = matched_allowed_root(config, &path)?;
    let content_digest = sha256_hex(content.as_bytes());

    Ok(LocalTextFileRead {
        path: path.display().to_string(),
        relative_path: relative_path(&allowed_root, &path),
        size_bytes: metadata.len(),
        content,
        audit: serde_json::json!({
            "operation": "read_text_file",
            "path": path.display().to_string(),
            "size_bytes": metadata.len(),
            "content_digest_sha256": content_digest,
        }),
    })
}

pub async fn stat_path(
    config: &HostedGatewayLocalAccessConfig,
    request: &LocalAccessRequest,
) -> anyhow::Result<LocalPathStat> {
    let path = validate_path(config, &request.path).await?;
    let metadata = tokio::fs::metadata(&path).await?;
    let allowed_root = matched_allowed_root(config, &path)?;

    Ok(LocalPathStat {
        path: path.display().to_string(),
        relative_path: relative_path(&allowed_root, &path),
        entry_type: entry_type(&metadata),
        size_bytes: metadata.is_file().then_some(metadata.len()),
        audit: serde_json::json!({
            "operation": "stat_path",
            "path": path.display().to_string(),
            "entry_type": entry_type(&metadata),
            "size_bytes": metadata.is_file().then_some(metadata.len()),
        }),
    })
}

pub async fn delete_path(
    config: &HostedGatewayLocalAccessConfig,
    request: &LocalAccessRequest,
) -> anyhow::Result<LocalPathDeletion> {
    if config.mode != "read_write" {
        return Err(anyhow!(
            "hosted gateway local access mode must be read_write before delete_path can run"
        ));
    }

    let path = validate_path(config, &request.path).await?;
    let metadata = tokio::fs::metadata(&path).await?;
    let allowed_root = matched_allowed_root(config, &path)?;
    let relative = relative_path(&allowed_root, &path);
    if relative == "." {
        return Err(anyhow!(
            "refusing to delete the approved working directory root"
        ));
    }

    let entry_type = entry_type(&metadata);
    if metadata.is_dir() {
        tokio::fs::remove_dir_all(&path).await?;
    } else if metadata.is_file() {
        tokio::fs::remove_file(&path).await?;
    } else {
        return Err(anyhow!("path is not a regular file or directory"));
    }

    Ok(LocalPathDeletion {
        path: path.display().to_string(),
        relative_path: relative,
        entry_type: entry_type.clone(),
        audit: serde_json::json!({
            "operation": "delete_path",
            "path": path.display().to_string(),
            "relative_path": relative_path(&allowed_root, &path),
            "entry_type": entry_type,
        }),
    })
}

/// Validate a path for write-targeting (file may not exist yet).
///
/// Resolves the parent directory, checks it falls within an allowed root and
/// is not excluded, then returns `(resolved_target, allowed_root)`.
pub async fn validate_write_target(
    config: &HostedGatewayLocalAccessConfig,
    path: &Path,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    if !config.enabled {
        return Err(anyhow!("hosted gateway local access is disabled"));
    }
    if config.mode != "read_write" {
        return Err(anyhow!(
            "hosted gateway local access mode must be read_write for write operations"
        ));
    }

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("write target has no parent directory"))?;
    let canonical_parent = tokio::fs::canonicalize(parent)
        .await
        .with_context(|| format!("parent directory {} does not exist", parent.display()))?;

    let allowed_root = matched_allowed_root(config, &canonical_parent)?;
    if path_is_excluded(config, &canonical_parent) {
        return Err(anyhow!(
            "parent directory is excluded by hosted gateway local access policy"
        ));
    }

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("write target has no file name component"))?;
    let resolved = canonical_parent.join(file_name);

    if path_is_excluded(config, &resolved) {
        return Err(anyhow!(
            "target path is excluded by hosted gateway local access policy"
        ));
    }

    Ok((resolved, allowed_root))
}

pub async fn write_text_file(
    config: &HostedGatewayLocalAccessConfig,
    request: &LocalAccessRequest,
    content: &str,
) -> anyhow::Result<LocalTextFileWrite> {
    let (resolved, allowed_root) = validate_write_target(config, &request.path).await?;

    if content.len() as u64 > config.max_file_bytes {
        return Err(anyhow!(
            "content size {} exceeds max_file_bytes {}",
            content.len(),
            config.max_file_bytes
        ));
    }

    let created = !resolved.exists();
    tokio::fs::write(&resolved, content)
        .await
        .with_context(|| format!("failed to write {}", resolved.display()))?;

    let bytes_written = content.len() as u64;
    let rel = relative_path(&allowed_root, &resolved);
    let content_digest = sha256_hex(content.as_bytes());

    Ok(LocalTextFileWrite {
        path: resolved.display().to_string(),
        relative_path: rel,
        bytes_written,
        created,
        audit: serde_json::json!({
            "operation": "write_text_file",
            "path": resolved.display().to_string(),
            "bytes_written": bytes_written,
            "created": created,
            "content_digest_sha256": content_digest,
        }),
    })
}

pub async fn create_directory(
    config: &HostedGatewayLocalAccessConfig,
    request: &LocalAccessRequest,
) -> anyhow::Result<LocalDirectoryCreation> {
    let (resolved, allowed_root) = validate_write_target(config, &request.path).await?;

    let already_existed = resolved.is_dir();
    tokio::fs::create_dir_all(&resolved)
        .await
        .with_context(|| format!("failed to create directory {}", resolved.display()))?;

    let rel = relative_path(&allowed_root, &resolved);

    Ok(LocalDirectoryCreation {
        path: resolved.display().to_string(),
        relative_path: rel,
        already_existed,
        audit: serde_json::json!({
            "operation": "create_directory",
            "path": resolved.display().to_string(),
            "already_existed": already_existed,
        }),
    })
}

pub async fn execute_command(
    config: &HostedGatewayLocalAccessConfig,
    request: &LocalAccessRequest,
    argv: &[String],
    working_directory: &Path,
) -> Result<LocalShellExecution, LocalCommandError> {
    execute_command_with_approval(config, request, argv, working_directory, None).await
}

pub async fn execute_command_with_approval(
    config: &HostedGatewayLocalAccessConfig,
    request: &LocalAccessRequest,
    argv: &[String],
    working_directory: &Path,
    approval: Option<(&LocalCommandApprovalStore, &str)>,
) -> Result<LocalShellExecution, LocalCommandError> {
    execute_command_with_approval_and_semaphore(
        config,
        request,
        argv,
        working_directory,
        approval,
        None,
    )
    .await
}

async fn execute_command_with_approval_and_semaphore(
    config: &HostedGatewayLocalAccessConfig,
    _request: &LocalAccessRequest,
    argv: &[String],
    working_directory: &Path,
    approval: Option<(&LocalCommandApprovalStore, &str)>,
    process_semaphore: Option<Arc<Semaphore>>,
) -> Result<LocalShellExecution, LocalCommandError> {
    let working_directory = validate_path(config, working_directory)
        .await
        .map_err(|error| LocalCommandError::PolicyDenied(error.to_string()))?;

    validate_command_argv(config, argv)
        .map_err(|error| LocalCommandError::PolicyDenied(error.to_string()))?;
    let program = argv
        .first()
        .ok_or_else(|| LocalCommandError::PolicyDenied("command argv is empty".to_string()))?;
    let args = &argv[1..];
    let command = render_command(argv);
    let command_digest = sha256_hex(command.as_bytes());
    let risk_level =
        normalize_shell_risk(classify_shell_command(&command, &working_directory, config).await);
    let risk_label = risk_level.as_str();
    let approval_required_levels = normalize_approval_required_levels(config)?;

    let process_permit: OwnedSemaphorePermit = match process_semaphore {
        Some(semaphore) => semaphore
            .try_acquire_owned()
            .map_err(|_| LocalCommandError::CapacityExceeded)?,
        None => verifier_child_pool()
            .try_acquire_process()
            .map_err(|_| LocalCommandError::CapacityExceeded)?,
    };
    let approval_grant_id = if approval_required_levels.contains(&risk_level) {
        let (store, grant_id) = approval.ok_or(LocalCommandError::ApprovalRequired)?;
        Some(
            store
                .consume_matching(grant_id, &command_digest, &working_directory, risk_level)
                .await?,
        )
    } else {
        None
    };

    let timeout = effective_timeout(config);
    let output_cap = effective_output_cap(config);
    let bounded = run_bounded_command(
        program,
        args,
        &working_directory,
        timeout,
        output_cap,
        process_permit,
    )
    .await?;
    let stdout_output = bounded.stdout;
    let stderr_output = bounded.stderr;
    let stdout = String::from_utf8_lossy(&stdout_output.bytes).to_string();
    let mut stderr = String::from_utf8_lossy(&stderr_output.bytes).to_string();
    if bounded.timed_out && stderr.is_empty() {
        stderr = format!("command timed out after {} seconds", timeout.as_secs());
    } else if let Some(stream) = bounded.output_limit_stream {
        if stderr.is_empty() {
            stderr = format!("{stream} exceeded the {output_cap}-byte output limit");
        }
    }

    Ok(LocalShellExecution {
        command: command.clone(),
        argv: argv.to_vec(),
        working_directory: working_directory.display().to_string(),
        exit_code: bounded.exit_code,
        stdout: stdout.clone(),
        stderr: stderr.clone(),
        timed_out: bounded.timed_out,
        stdout_truncated: stdout_output.truncated,
        stderr_truncated: stderr_output.truncated,
        risk_level: risk_label.to_string(),
        audit: serde_json::json!({
            "operation": "command_execute",
            "command_digest_sha256": sha256_hex(command.as_bytes()),
            "program": program,
            "working_directory": working_directory.display().to_string(),
            "exit_code": bounded.exit_code,
            "timed_out": bounded.timed_out,
            "timeout_seconds": timeout.as_secs(),
            "stdout_len": stdout_output.total_bytes,
            "stderr_len": stderr_output.total_bytes,
            "stdout_truncated": stdout_output.truncated,
            "stderr_truncated": stderr_output.truncated,
            "risk_level": risk_label,
            "approval_grant_id": approval_grant_id,
            "output_limit_stream": bounded.output_limit_stream,
        }),
    })
}

pub async fn execute_shell(
    config: &HostedGatewayLocalAccessConfig,
    request: &LocalAccessRequest,
    command: &str,
    working_directory: &Path,
) -> Result<LocalShellExecution, LocalCommandError> {
    if contains_shell_syntax(command) {
        deny_command(
            "shell_syntax",
            command.split_whitespace().next().unwrap_or(""),
            "shell syntax is not supported; submit structured argv instead",
        );
        return Err(LocalCommandError::PolicyDenied(
            "shell syntax is not supported by hosted gateway local access; submit structured argv instead"
                .to_string(),
        ));
    }
    let argv: Vec<String> = command
        .split_whitespace()
        .map(ToString::to_string)
        .collect();
    execute_command(config, request, &argv, working_directory).await
}

fn validate_command_argv(
    config: &HostedGatewayLocalAccessConfig,
    argv: &[String],
) -> anyhow::Result<()> {
    let Some(program) = argv.first().map(String::as_str) else {
        deny_command("empty_argv", "", "command argv is empty");
        return Err(anyhow!("command argv is empty"));
    };

    if argv.iter().any(|arg| arg.is_empty()) {
        deny_command(
            "empty_argument",
            program,
            "command argv contains an empty argument",
        );
        return Err(anyhow!("command argv contains an empty argument"));
    }
    if argv.iter().any(|arg| arg.as_bytes().contains(&0)) {
        deny_command("nul_argument", program, "command argv contains a NUL byte");
        return Err(anyhow!("command argv contains a NUL byte"));
    }
    if argv.iter().any(|arg| contains_shell_syntax(arg)) {
        deny_command(
            "shell_syntax",
            program,
            "shell metacharacters are not accepted in structured argv",
        );
        return Err(anyhow!(
            "shell metacharacters are not accepted in hosted gateway local access argv"
        ));
    }
    if is_shell_program(program) {
        deny_command(
            "shell_program",
            program,
            "shell interpreters are not allowed",
        );
        return Err(anyhow!(
            "shell interpreters are not allowed for hosted gateway local access"
        ));
    }

    if config
        .blocked_commands
        .iter()
        .filter_map(|blocked| parse_config_command(blocked))
        .any(|blocked| blocked == argv)
    {
        deny_command(
            "blocked_command",
            program,
            "command exactly matches blocked command policy",
        );
        return Err(anyhow!(
            "command is blocked by hosted gateway local access policy"
        ));
    }

    if !config
        .allowed_commands
        .iter()
        .filter_map(|allowed| parse_config_command(allowed))
        .any(|allowed| allowed == argv)
    {
        deny_command(
            "not_allowlisted",
            program,
            "command argv does not exactly match allowed command policy",
        );
        return Err(anyhow!(
            "command argv is not in the hosted gateway allowed commands"
        ));
    }

    Ok(())
}

fn deny_command(reason: &'static str, program: &str, message: &'static str) {
    tracing::warn!(
        reason,
        program,
        message,
        "hosted gateway local access command denied"
    );
}

fn parse_config_command(value: &str) -> Option<Vec<String>> {
    let argv: Vec<String> = value
        .split_whitespace()
        .map(ToString::to_string)
        .filter(|arg| !arg.is_empty())
        .collect();
    (!argv.is_empty()).then_some(argv)
}

fn contains_shell_syntax(value: &str) -> bool {
    const METACHARS: &[char] = &[';', '|', '&', '<', '>', '`', '$', '\n', '\r'];
    value.contains("&&") || value.contains("||") || value.chars().any(|c| METACHARS.contains(&c))
}

fn is_shell_program(program: &str) -> bool {
    let program_name = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program)
        .to_ascii_lowercase();
    matches!(
        program_name.as_str(),
        "sh" | "bash"
            | "zsh"
            | "fish"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
    )
}

fn render_command(argv: &[String]) -> String {
    argv.join(" ")
}

fn effective_timeout(config: &HostedGatewayLocalAccessConfig) -> Duration {
    let configured = if config.command_timeout_seconds == 0 {
        HostedGatewayLocalAccessConfig::default().command_timeout_seconds
    } else {
        config.command_timeout_seconds
    };
    clamp_timeout(Duration::from_secs(configured))
}

fn effective_output_cap(config: &HostedGatewayLocalAccessConfig) -> usize {
    let hard_cap = verifier_child_pool().config().stdout_max_bytes;
    let cap = if config.max_output_bytes == 0 {
        HostedGatewayLocalAccessConfig::default().max_output_bytes
    } else {
        config.max_output_bytes
    };
    usize::try_from(cap).unwrap_or(hard_cap).min(hard_cap)
}

async fn run_bounded_command(
    program: &str,
    args: &[String],
    working_directory: &Path,
    timeout: Duration,
    output_cap: usize,
    _permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<BoundedCommandOutcome, LocalCommandError> {
    let mut child = tokio::process::Command::new(program);
    child
        .args(args)
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = child.spawn()?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (limit_sender, mut limit_receiver) = tokio::sync::mpsc::unbounded_channel::<&'static str>();
    let stdout_sender = limit_sender.clone();
    let stdout_reader = tokio::spawn(async move {
        read_bounded_async(stdout, output_cap, "stdout", stdout_sender).await
    });
    let stderr_reader = tokio::spawn(async move {
        read_bounded_async(stderr, output_cap, "stderr", limit_sender).await
    });

    enum Termination {
        Exited(std::process::ExitStatus),
        TimedOut,
        OutputLimited(&'static str),
    }

    let termination = tokio::select! {
        biased;
        Some(stream) = limit_receiver.recv() => Termination::OutputLimited(stream),
        status = child.wait() => Termination::Exited(status?),
        _ = tokio::time::sleep(timeout) => Termination::TimedOut,
    };
    if !matches!(termination, Termination::Exited(_)) {
        if let Err(error) = child.kill().await {
            tracing::warn!(
                program,
                error = %error,
                "failed to kill bounded local access command"
            );
        }
        let _ = tokio::time::timeout(READER_SHUTDOWN_TIMEOUT, child.wait()).await;
    }

    let stdout = finish_output_reader(stdout_reader, "stdout").await?;
    let stderr = finish_output_reader(stderr_reader, "stderr").await?;
    // Prefer stream-limit evidence over a racing clean exit: short commands can
    // finish before `select!` observes the limit channel, which would otherwise
    // report a success exit code after truncation.
    let (exit_code, timed_out, output_limit_stream) = match termination {
        Termination::TimedOut => (None, true, None),
        Termination::OutputLimited(stream) => (None, false, Some(stream)),
        Termination::Exited(status) => {
            if let Ok(stream) = limit_receiver.try_recv() {
                (None, false, Some(stream))
            } else if stdout.truncated {
                (None, false, Some("stdout"))
            } else if stderr.truncated {
                (None, false, Some("stderr"))
            } else {
                (status.code(), false, None)
            }
        }
    };

    Ok(BoundedCommandOutcome {
        stdout,
        stderr,
        exit_code,
        timed_out,
        output_limit_stream,
    })
}

async fn read_bounded_async<R>(
    reader: Option<R>,
    cap: usize,
    stream: &'static str,
    limit_sender: tokio::sync::mpsc::UnboundedSender<&'static str>,
) -> std::io::Result<BoundedOutput>
where
    R: AsyncRead + Unpin,
{
    let Some(mut reader) = reader else {
        return Ok(BoundedOutput {
            bytes: Vec::new(),
            total_bytes: 0,
            truncated: false,
        });
    };
    let mut bytes = Vec::with_capacity(cap.min(8192));
    let mut total_bytes = 0_u64;
    let mut buffer = [0_u8; 8192];

    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(read as u64);
        if bytes.len() < cap {
            let remaining = cap - bytes.len();
            let keep = remaining.min(read);
            bytes.extend_from_slice(&buffer[..keep]);
        }
        if total_bytes > cap as u64 {
            let _ = limit_sender.send(stream);
            break;
        }
    }

    Ok(BoundedOutput {
        truncated: total_bytes > bytes.len() as u64,
        bytes,
        total_bytes,
    })
}

async fn finish_output_reader(
    mut reader: tokio::task::JoinHandle<std::io::Result<BoundedOutput>>,
    stream: &str,
) -> Result<BoundedOutput, LocalCommandError> {
    match tokio::time::timeout(READER_SHUTDOWN_TIMEOUT, &mut reader).await {
        Ok(Ok(Ok(output))) => Ok(output),
        Ok(Ok(Err(error))) => Err(LocalCommandError::OutputReader(format!(
            "failed to read command {stream}: {error}"
        ))),
        Ok(Err(error)) => Err(LocalCommandError::OutputReader(format!(
            "failed to join command {stream} reader: {error}"
        ))),
        Err(_) => {
            reader.abort();
            let _ = reader.await;
            Ok(BoundedOutput {
                bytes: Vec::new(),
                total_bytes: 0,
                truncated: true,
            })
        }
    }
}

fn normalize_shell_risk(level: ShellRiskLevel) -> NormalizedRiskLevel {
    match level {
        ShellRiskLevel::Safe => NormalizedRiskLevel::Safe,
        ShellRiskLevel::Moderate => NormalizedRiskLevel::Moderate,
        ShellRiskLevel::Destructive => NormalizedRiskLevel::High,
        ShellRiskLevel::Critical => NormalizedRiskLevel::Critical,
    }
}

fn normalize_risk_level(value: &str) -> Result<NormalizedRiskLevel, LocalCommandError> {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "safe" | "low" => Ok(NormalizedRiskLevel::Safe),
        "moderate" | "medium" => Ok(NormalizedRiskLevel::Moderate),
        "destructive" | "high" => Ok(NormalizedRiskLevel::High),
        "critical" => Ok(NormalizedRiskLevel::Critical),
        _ => Err(LocalCommandError::UnknownRiskClassification(
            value.trim().to_string(),
        )),
    }
}

fn normalize_approval_required_levels(
    config: &HostedGatewayLocalAccessConfig,
) -> Result<HashSet<NormalizedRiskLevel>, LocalCommandError> {
    config
        .approval_required_risk_levels
        .iter()
        .map(|value| normalize_risk_level(value))
        .collect()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn prune_consumed_grants(state: &mut ApprovalGrantState, now: DateTime<Utc>) {
    state.consumed.retain(|_, expires_at| *expires_at > now);
}

fn matched_allowed_root(
    config: &HostedGatewayLocalAccessConfig,
    canonical: &Path,
) -> anyhow::Result<PathBuf> {
    config
        .allowed_roots
        .iter()
        .filter_map(|root| {
            Path::new(root)
                .canonicalize()
                .ok()
                .filter(|allowed_root| canonical.starts_with(allowed_root))
        })
        .max_by_key(|root| root.components().count())
        .ok_or_else(|| anyhow!("path is outside hosted gateway allowed roots"))
}

fn path_is_excluded(config: &HostedGatewayLocalAccessConfig, canonical: &Path) -> bool {
    let rendered = canonical.to_string_lossy();
    config
        .exclude_globs
        .iter()
        .any(|pattern| !pattern.is_empty() && rendered.contains(pattern.trim_matches('*')))
}

fn relative_path(allowed_root: &Path, canonical: &Path) -> String {
    canonical
        .strip_prefix(allowed_root)
        .ok()
        .map(|path| {
            let rendered = path.display().to_string();
            if rendered.is_empty() {
                ".".to_string()
            } else {
                rendered
            }
        })
        .unwrap_or_else(|| canonical.display().to_string())
}

fn entry_type(metadata: &std::fs::Metadata) -> String {
    if metadata.is_dir() {
        "directory".to_string()
    } else if metadata.is_file() {
        "file".to_string()
    } else {
        "other".to_string()
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    fn local_access_config(root: &Path) -> HostedGatewayLocalAccessConfig {
        HostedGatewayLocalAccessConfig {
            enabled: true,
            allowed_roots: vec![root.display().to_string()],
            max_file_bytes: 1_024,
            ..HostedGatewayLocalAccessConfig::default()
        }
    }

    fn read_write_config(root: &Path) -> HostedGatewayLocalAccessConfig {
        HostedGatewayLocalAccessConfig {
            mode: "read_write".to_string(),
            ..local_access_config(root)
        }
    }

    fn command_config(
        root: &Path,
        allowed_commands: Vec<String>,
    ) -> HostedGatewayLocalAccessConfig {
        HostedGatewayLocalAccessConfig {
            enabled: true,
            allowed_roots: vec![root.display().to_string()],
            allowed_commands,
            command_timeout_seconds: 5,
            max_output_bytes: 1_024,
            ..HostedGatewayLocalAccessConfig::default()
        }
    }

    fn approval_grant(
        id: &str,
        argv: &[String],
        working_directory: &Path,
        risk_level: &str,
        expires_at: DateTime<Utc>,
    ) -> LocalCommandApprovalGrant {
        LocalCommandApprovalGrant {
            id: id.to_string(),
            command_digest_sha256: sha256_hex(render_command(argv).as_bytes()),
            working_directory: working_directory.display().to_string(),
            risk_level: risk_level.to_string(),
            expires_at,
        }
    }

    #[cfg(unix)]
    fn touch_program() -> &'static str {
        if Path::new("/usr/bin/touch").is_file() {
            "/usr/bin/touch"
        } else {
            "/bin/touch"
        }
    }

    fn request(path: impl Into<PathBuf>) -> LocalAccessRequest {
        LocalAccessRequest { path: path.into() }
    }

    fn rendered_relative(parts: &[&str]) -> String {
        let mut path = PathBuf::new();
        for part in parts {
            path.push(part);
        }
        path.display().to_string()
    }

    #[test]
    fn command_helpers_apply_defaults_and_parse_expected_values() {
        assert_eq!(
            parse_config_command("  /usr/bin/env   printf   "),
            Some(vec!["/usr/bin/env".to_string(), "printf".to_string()])
        );
        assert_eq!(parse_config_command("   "), None);
        assert!(contains_shell_syntax("printf && whoami"));
        assert!(contains_shell_syntax("printf $HOME"));
        assert!(!contains_shell_syntax("printf hello"));
        assert!(is_shell_program("/bin/bash"));
        assert!(is_shell_program("pwsh.exe"));
        assert!(!is_shell_program("/usr/bin/env"));
        assert_eq!(
            render_command(&["alpha".to_string(), "beta".to_string()]),
            "alpha beta"
        );

        let config = HostedGatewayLocalAccessConfig {
            command_timeout_seconds: 0,
            max_output_bytes: 0,
            ..HostedGatewayLocalAccessConfig::default()
        };
        let defaults = HostedGatewayLocalAccessConfig::default();
        assert_eq!(
            effective_timeout(&config),
            Duration::from_secs(defaults.command_timeout_seconds)
        );
        assert_eq!(
            effective_output_cap(&config),
            defaults.max_output_bytes as usize
        );
    }

    #[test]
    fn validate_command_argv_covers_policy_and_shell_guards() {
        let root = tempdir().expect("tempdir");
        let config = HostedGatewayLocalAccessConfig {
            enabled: true,
            allowed_roots: vec![root.path().display().to_string()],
            allowed_commands: vec!["/bin/echo ok".to_string()],
            blocked_commands: vec!["/bin/rm -rf".to_string()],
            ..HostedGatewayLocalAccessConfig::default()
        };

        let error = validate_command_argv(&config, &[]).expect_err("empty argv");
        assert!(error.to_string().contains("empty"));

        let error = validate_command_argv(&config, &["/bin/echo".to_string(), String::new()])
            .expect_err("empty argument");
        assert!(error.to_string().contains("empty argument"));

        let error =
            validate_command_argv(&config, &["/bin/echo".to_string(), "ok\0bad".to_string()])
                .expect_err("nul byte");
        assert!(error.to_string().contains("NUL"));

        let error =
            validate_command_argv(&config, &["/bin/echo".to_string(), "ok;bad".to_string()])
                .expect_err("shell metacharacters");
        assert!(error.to_string().contains("metacharacters"));

        let error = validate_command_argv(&config, &["/bin/bash".to_string(), "-lc".to_string()])
            .expect_err("shell program");
        assert!(error.to_string().contains("shell interpreters"));

        let error = validate_command_argv(&config, &["/bin/rm".to_string(), "-rf".to_string()])
            .expect_err("blocked command");
        assert!(error.to_string().contains("blocked"));

        let error = validate_command_argv(&config, &["/bin/echo".to_string(), "nope".to_string()])
            .expect_err("not allowlisted");
        assert!(error.to_string().contains("allowed commands"));

        validate_command_argv(&config, &["/bin/echo".to_string(), "ok".to_string()])
            .expect("allowlisted argv");
    }

    #[tokio::test]
    async fn bounded_reader_tracks_total_bytes_and_reader_errors() {
        let (mut writer, reader) = tokio::io::duplex(16);
        let write_task = tokio::spawn(async move {
            writer.write_all(b"abcdef").await.expect("write bytes");
        });
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let output = read_bounded_async(Some(reader), 4, "stdout", sender)
            .await
            .expect("bounded read");
        write_task.await.expect("writer task");
        assert_eq!(output.bytes, b"abcd");
        assert_eq!(output.total_bytes, 6);
        assert!(output.truncated);
        assert_eq!(receiver.recv().await, Some("stdout"));
    }

    #[test]
    fn path_helpers_choose_deepest_root_and_render_expected_paths() {
        let dir = tempdir().expect("tempdir");
        let nested = dir.path().join("nested");
        std::fs::create_dir_all(&nested).expect("create nested");

        let file_path = nested.join("file.txt");
        std::fs::write(&file_path, "hello").expect("write file");
        let file_metadata = std::fs::metadata(&file_path).expect("file metadata");
        let dir_metadata = std::fs::metadata(&nested).expect("dir metadata");

        let config = HostedGatewayLocalAccessConfig {
            enabled: true,
            allowed_roots: vec![
                dir.path().display().to_string(),
                nested.display().to_string(),
            ],
            exclude_globs: vec!["*blocked*".to_string()],
            ..HostedGatewayLocalAccessConfig::default()
        };

        let canonical_nested = nested.canonicalize().expect("canonical nested");
        let canonical_file = file_path.canonicalize().expect("canonical file");
        assert_eq!(
            matched_allowed_root(&config, &canonical_file).expect("matched root"),
            canonical_nested
        );
        assert_eq!(relative_path(&canonical_nested, &canonical_nested), ".");
        assert_eq!(
            relative_path(&canonical_nested, &canonical_file),
            "file.txt"
        );
        assert!(path_is_excluded(
            &config,
            &nested
                .join("blocked.txt")
                .canonicalize()
                .unwrap_or_else(|_| nested.join("blocked.txt"))
        ));
        assert_eq!(entry_type(&file_metadata), "file");
        assert_eq!(entry_type(&dir_metadata), "directory");
    }

    #[tokio::test]
    async fn validate_path_summary_and_stat_report_canonical_metadata() {
        let dir = tempdir().expect("tempdir");
        let reports = dir.path().join("reports");
        std::fs::create_dir_all(&reports).expect("create reports dir");
        let file_path = reports.join("summary.txt");
        std::fs::write(&file_path, "hello").expect("write file");

        let config = local_access_config(dir.path());
        let validated = validate_path(&config, &file_path)
            .await
            .expect("validate path");
        assert_eq!(validated, file_path.canonicalize().expect("canonical file"));

        let summary = read_file_summary(&config, &request(&file_path))
            .await
            .expect("read file summary");
        assert_eq!(summary.size_bytes, 5);
        assert_eq!(
            summary.audit["operation"].as_str(),
            Some("read_file_summary")
        );

        let file_stat = stat_path(&config, &request(&file_path))
            .await
            .expect("file stat");
        assert_eq!(
            file_stat.relative_path,
            rendered_relative(&["reports", "summary.txt"])
        );
        assert_eq!(file_stat.entry_type, "file");
        assert_eq!(file_stat.size_bytes, Some(5));

        let dir_stat = stat_path(&config, &request(&reports))
            .await
            .expect("directory stat");
        assert_eq!(dir_stat.relative_path, "reports");
        assert_eq!(dir_stat.entry_type, "directory");
        assert_eq!(dir_stat.size_bytes, None);

        let disabled_error = validate_path(&HostedGatewayLocalAccessConfig::default(), &file_path)
            .await
            .expect_err("disabled config");
        assert!(disabled_error.to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn list_directory_skips_excluded_entries_and_records_audit() {
        let dir = tempdir().expect("tempdir");
        std::fs::write(dir.path().join("zeta.txt"), "zeta").expect("write zeta");
        std::fs::write(dir.path().join("alpha.txt"), "alpha").expect("write alpha");
        std::fs::write(dir.path().join("secret.txt"), "secret").expect("write secret");
        std::fs::create_dir(dir.path().join("reports")).expect("create reports");

        let mut config = local_access_config(dir.path());
        config.exclude_globs = vec!["*secret*".to_string()];

        let listing = list_directory(&config, &request(dir.path()))
            .await
            .expect("list directory");
        let relative_paths: Vec<&str> = listing
            .entries
            .iter()
            .map(|entry| entry.relative_path.as_str())
            .collect();
        assert_eq!(relative_paths, vec!["alpha.txt", "reports", "zeta.txt"]);
        assert_eq!(listing.audit["operation"].as_str(), Some("list_directory"));
        assert_eq!(listing.audit["skipped_entries"].as_u64(), Some(1));
    }

    #[tokio::test]
    async fn read_text_file_rejects_invalid_utf8_without_binary_nul() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("invalid.txt");
        std::fs::write(&file_path, [0xf0, 0x28, 0x8c, 0x28]).expect("write invalid utf8");

        let error = read_text_file(&local_access_config(dir.path()), &request(file_path))
            .await
            .expect_err("invalid utf8 should be rejected");
        assert!(error.to_string().contains("UTF-8"));
    }

    #[tokio::test]
    async fn validate_write_target_rejects_mode_parent_and_target_violations() {
        let dir = tempdir().expect("tempdir");
        let safe_dir = dir.path().join("safe");
        let blocked_dir = dir.path().join("blocked");
        std::fs::create_dir_all(&safe_dir).expect("create safe dir");
        std::fs::create_dir_all(&blocked_dir).expect("create blocked dir");

        let read_only_error =
            validate_write_target(&local_access_config(dir.path()), &safe_dir.join("note.txt"))
                .await
                .expect_err("read-only mode");
        assert!(read_only_error.to_string().contains("read_write"));

        let missing_parent_error = validate_write_target(
            &read_write_config(dir.path()),
            &dir.path().join("missing").join("note.txt"),
        )
        .await
        .expect_err("missing parent");
        assert!(missing_parent_error.to_string().contains("does not exist"));

        let mut blocked_parent_config = read_write_config(dir.path());
        blocked_parent_config.exclude_globs = vec!["*blocked*".to_string()];
        let parent_error =
            validate_write_target(&blocked_parent_config, &blocked_dir.join("note.txt"))
                .await
                .expect_err("blocked parent");
        assert!(parent_error
            .to_string()
            .contains("parent directory is excluded"));

        let mut blocked_target_config = read_write_config(dir.path());
        blocked_target_config.exclude_globs = vec!["*blocked.txt*".to_string()];
        let target_error =
            validate_write_target(&blocked_target_config, &safe_dir.join("blocked.txt"))
                .await
                .expect_err("blocked target");
        assert!(target_error.to_string().contains("target path is excluded"));
    }

    #[tokio::test]
    async fn write_create_and_delete_directory_paths_report_expected_flags() {
        let dir = tempdir().expect("tempdir");
        let config = read_write_config(dir.path());

        let file_path = dir.path().join("note.txt");
        let created = write_text_file(&config, &request(&file_path), "alpha")
            .await
            .expect("create file");
        assert!(created.created);
        assert_eq!(created.bytes_written, 5);
        assert_eq!(created.relative_path, "note.txt");
        assert_eq!(
            std::fs::read_to_string(&file_path).expect("read file"),
            "alpha"
        );

        let overwritten = write_text_file(&config, &request(&file_path), "beta")
            .await
            .expect("overwrite file");
        assert!(!overwritten.created);
        assert_eq!(overwritten.bytes_written, 4);
        assert_eq!(
            std::fs::read_to_string(&file_path).expect("read file"),
            "beta"
        );

        let reports = dir.path().join("reports");
        let created_dir = create_directory(&config, &request(&reports))
            .await
            .expect("create directory");
        assert!(!created_dir.already_existed);
        assert_eq!(created_dir.relative_path, "reports");

        let existing_dir = create_directory(&config, &request(&reports))
            .await
            .expect("create existing directory");
        assert!(existing_dir.already_existed);

        std::fs::write(reports.join("child.txt"), "child").expect("write child");
        let deleted = delete_path(&config, &request(&reports))
            .await
            .expect("delete directory");
        assert_eq!(deleted.entry_type, "directory");
        assert_eq!(deleted.relative_path, "reports");
        assert!(!reports.exists());
    }

    #[tokio::test]
    async fn delete_path_rejects_read_only_mode() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("note.txt");
        std::fs::write(&file_path, "note").expect("write file");

        let error = delete_path(&local_access_config(dir.path()), &request(file_path))
            .await
            .expect_err("delete should require read_write");
        assert!(error.to_string().contains("read_write"));
    }

    #[test]
    fn verifier_timeout_and_stream_caps_have_hard_maxima() {
        let config = HostedGatewayLocalAccessConfig {
            command_timeout_seconds: u64::MAX,
            max_output_bytes: u64::MAX,
            ..HostedGatewayLocalAccessConfig::default()
        };

        assert_eq!(
            effective_timeout(&config),
            crate::gateway::bounded_child::HARD_TIMEOUT
        );
        assert_eq!(
            effective_output_cap(&config),
            verifier_child_pool().config().stdout_max_bytes
        );
        assert_eq!(
            crate::gateway::bounded_child::BoundedChildConfig::compiled_defaults().process_capacity,
            crate::gateway::bounded_child::BoundedChildConfig::compiled_defaults().process_capacity
        );
        assert_eq!(
            crate::gateway::bounded_child::BoundedChildConfig::compiled_defaults().process_capacity,
            16
        );
        assert_eq!(
            crate::gateway::bounded_child::HARD_TIMEOUT,
            Duration::from_secs(300)
        );
        assert_eq!(
            verifier_child_pool().config().stdout_max_bytes,
            8 * 1024 * 1024
        );
        assert_eq!(
            verifier_child_pool().config().stderr_max_bytes,
            8 * 1024 * 1024
        );
    }
}
