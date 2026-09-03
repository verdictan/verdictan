// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use fs2::FileExt;

use crate::error::CliError;
use crate::instances::{GatewayInstanceSpec, GatewayInstanceStatus};
use crate::persistence::{atomic_write_json, sha256_hex};

pub const STATE_FILE_NAME: &str = "supervisor-state.json";
pub const BACKUP_STATE_FILE_NAME: &str = "supervisor-state.json.bak";
pub const WAL_FILE_NAME: &str = "supervisor-state.wal";
const LOCK_FILE_NAME: &str = "supervisor-state.lock";
const LOCK_RETRY_DELAY_MS: u64 = 10;
const LOCK_TIMEOUT_SECS: u64 = 5;

#[derive(Clone, Debug, serde::Serialize)]
pub struct SupervisorStateMetadata {
    pub state_dir: String,
    pub recovered_from_backup: bool,
    pub recovery_message: Option<String>,
    pub wal_recovered: bool,
    pub state_checksum: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InstanceRecord {
    pub spec: GatewayInstanceSpec,
    pub status: GatewayInstanceStatus,
    #[serde(default)]
    pub operations_history: Vec<OperationHistoryEntry>,
    #[serde(default)]
    pub rollout_plan: Option<RolloutPlan>,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationAction {
    Reload,
    Reconcile,
    CancelReconcile,
    Revert,
    Install,
    Start,
    Stop,
    Uninstall,
    UpgradePlan,
    UpgradeApply,
    UpgradeRollback,
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    Succeeded,
    RolledBack,
    Failed,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct OperationHistoryEntry {
    pub action: OperationAction,
    pub outcome: OperationOutcome,
    pub reason: Option<String>,
    pub previous_version: Option<String>,
    pub previous_sha256: Option<String>,
    pub target_version: Option<String>,
    pub target_sha256: Option<String>,
    pub active_version: Option<String>,
    pub active_sha256: Option<String>,
    pub recorded_at: String,
}

// --- Rollout strategy and plan (item #4) ---

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RolloutStrategy {
    AllAtOnce,
    Canary,
    Batch,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RolloutPlan {
    pub strategy: RolloutStrategy,
    /// Target percentage of instances to update (0–100).
    pub target_percentage: u8,
    /// Pause the rollout if any instance fails health-check.
    pub pause_on_error: bool,
    /// Instance IDs that have completed this rollout.
    pub completed_instances: Vec<String>,
    /// Instance IDs that failed during this rollout.
    pub failed_instances: Vec<String>,
    pub started_at: String,
    pub updated_at: String,
}

// --- Write-ahead log entry (item #5) ---

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct WalEntry {
    pub operation: String,
    pub instance_id: Option<String>,
    pub payload: serde_json::Value,
    pub timestamp: String,
    pub committed: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct InstanceSummary {
    pub instance_id: String,
    pub gateway_id: String,
    pub name: String,
    pub listen_addr: String,
    pub lifecycle: String,
    pub observed_config_version: Option<String>,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct PersistedSupervisorState {
    schema_version: u32,
    updated_at: String,
    /// CLI-FIND-RACE-003: Monotonic write version for compare-and-swap protection.
    /// Incremented on every persist; stale stores are rejected when the on-disk
    /// version has advanced beyond the in-memory expected version.
    #[serde(default)]
    write_version: u64,
    instances: BTreeMap<String, InstanceRecord>,
    action_checkpoints: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PersistedSupervisorEnvelope {
    schema_version: u32,
    updated_at: String,
    checksum_sha256: String,
    payload: PersistedSupervisorState,
}

pub const MAX_OPERATION_HISTORY_ENTRIES: usize = 25;

pub struct SupervisorStateStore {
    state_dir: PathBuf,
    state_file: PathBuf,
    backup_file: PathBuf,
    lock_file: PathBuf,
    persisted: PersistedSupervisorState,
    recovered_from_backup: bool,
    recovery_message: Option<String>,
    wal_recovered: bool,
    state_checksum: Option<String>,
    /// CLI-FIND-RACE-003: The write_version loaded at open time. Used by CAS
    /// persist to detect concurrent modifications from other processes.
    loaded_write_version: u64,
}

impl SupervisorStateStore {
    pub fn load(state_dir: impl Into<PathBuf>) -> Result<Self, CliError> {
        let state_dir = state_dir.into();
        let state_file = state_dir.join(STATE_FILE_NAME);
        let backup_file = state_dir.join(BACKUP_STATE_FILE_NAME);
        let lock_file = state_dir.join(LOCK_FILE_NAME);
        let wal_file = state_dir.join(WAL_FILE_NAME);

        let (mut persisted, recovered_from_backup, recovery_message, state_checksum) =
            if state_file.exists() {
                let bytes = std::fs::read(&state_file).map_err(|e| {
                    CliError::internal(format!(
                        "failed to read supervisor state {}: {e}",
                        state_file.display()
                    ))
                })?;
                match decode_state_bytes(&bytes) {
                    Ok((persisted, checksum)) => {
                        repair_backup_from_primary_if_needed(&backup_file, &persisted)?;
                        (persisted, false, None, checksum)
                    }
                    Err(primary_error) if backup_file.exists() => {
                        let (backup, backup_checksum) =
                            load_backup_state(&backup_file, Some(&primary_error))?;
                        repair_state_from_backup(&state_file, &backup_file, &backup)?;
                        (
                            backup,
                            true,
                            Some(format!(
                            "Recovered supervisor state from backup after primary corruption: {}",
                            primary_error
                        )),
                            backup_checksum,
                        )
                    }
                    Err(e) => {
                        return Err(CliError::internal(format!(
                            "invalid supervisor state {}: {e}",
                            state_file.display()
                        )))
                    }
                }
            } else if backup_file.exists() {
                let (backup, backup_checksum) = load_backup_state(&backup_file, None)?;
                repair_state_from_backup(&state_file, &backup_file, &backup)?;
                (
                    backup,
                    true,
                    Some(format!(
                        "Recovered supervisor state from backup after primary state {} was missing",
                        state_file.display()
                    )),
                    backup_checksum,
                )
            } else {
                (
                    PersistedSupervisorState {
                        schema_version: 1,
                        updated_at: Utc::now().to_rfc3339(),
                        ..PersistedSupervisorState::default()
                    },
                    false,
                    None,
                    None,
                )
            };

        let wal_recovered = if wal_file.exists() {
            let entries = read_wal_entries_from_path(&wal_file);
            if !entries.is_empty() {
                // CLI-FIND-LOW-003: Idempotent WAL recovery — replay committed entries,
                // discard uncommitted entries, then remove the WAL file.
                replay_committed_wal_entries(&mut persisted, &entries);
                // Clear WAL after successful replay to prevent duplicate application.
                let _ = std::fs::remove_file(&wal_file);
                true
            } else {
                false
            }
        } else {
            false
        };

        let loaded_write_version = persisted.write_version;

        Ok(Self {
            state_dir,
            state_file,
            backup_file,
            lock_file,
            persisted,
            recovered_from_backup,
            recovery_message,
            wal_recovered,
            state_checksum,
            loaded_write_version,
        })
    }

    pub fn create_instance(&mut self, spec: GatewayInstanceSpec) -> Result<(), CliError> {
        spec.validate()?;
        let key = spec.instance_id.as_str().to_string();
        if self.persisted.instances.contains_key(&key) {
            return Err(CliError::user(format!("instance {} already exists", key)));
        }
        self.persisted.instances.insert(
            key,
            InstanceRecord {
                spec,
                status: GatewayInstanceStatus::default(),
                operations_history: Vec::new(),
                rollout_plan: None,
            },
        );
        self.persist()
    }

    pub fn list_instances(&self) -> Vec<InstanceSummary> {
        self.persisted
            .instances
            .values()
            .map(|record| InstanceSummary {
                instance_id: record.spec.instance_id.as_str().to_string(),
                gateway_id: record.spec.gateway_id.clone(),
                name: record.spec.name.clone(),
                listen_addr: record.spec.listen_addr.clone(),
                lifecycle: format!("{:?}", record.status.lifecycle).to_ascii_lowercase(),
                observed_config_version: record.status.observed_config_version.clone(),
                updated_at: record.status.updated_at.clone(),
            })
            .collect()
    }

    pub fn get_instance(&self, instance_id: &str) -> Option<&InstanceRecord> {
        self.persisted.instances.get(instance_id)
    }

    pub fn append_operation_history(
        &mut self,
        instance_id: &str,
        entry: OperationHistoryEntry,
    ) -> Result<(), CliError> {
        let record = self
            .persisted
            .instances
            .get_mut(instance_id)
            .ok_or_else(|| CliError::user(format!("instance {} does not exist", instance_id)))?;
        record.operations_history.push(entry);
        if record.operations_history.len() > MAX_OPERATION_HISTORY_ENTRIES {
            let excess = record.operations_history.len() - MAX_OPERATION_HISTORY_ENTRIES;
            record.operations_history.drain(0..excess);
        }
        self.persist()
    }

    pub fn set_status(
        &mut self,
        instance_id: &str,
        status: GatewayInstanceStatus,
    ) -> Result<(), CliError> {
        let record = self
            .persisted
            .instances
            .get_mut(instance_id)
            .ok_or_else(|| CliError::user(format!("instance {} does not exist", instance_id)))?;
        record.status = status;
        self.persist()
    }

    pub fn set_rollout_plan(
        &mut self,
        instance_id: &str,
        plan: Option<RolloutPlan>,
    ) -> Result<(), CliError> {
        let record = self
            .persisted
            .instances
            .get_mut(instance_id)
            .ok_or_else(|| CliError::user(format!("instance {} does not exist", instance_id)))?;
        record.rollout_plan = plan;
        self.persist()
    }

    fn is_action_applied(&self, instance_id: &str, action_id: &str) -> bool {
        self.persisted
            .action_checkpoints
            .get(instance_id)
            .map(|items| items.contains(action_id))
            .unwrap_or(false)
    }

    pub fn mark_action_applied(
        &mut self,
        instance_id: &str,
        action_id: impl Into<String>,
    ) -> Result<(), CliError> {
        self.persisted
            .action_checkpoints
            .entry(instance_id.to_string())
            .or_default()
            .insert(action_id.into());
        if let Some(record) = self.persisted.instances.get_mut(instance_id) {
            record.status.last_checkpoint_at = Some(Utc::now().to_rfc3339());
        }
        self.persist()
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn metadata(&self) -> SupervisorStateMetadata {
        SupervisorStateMetadata {
            state_dir: self.state_dir.display().to_string(),
            recovered_from_backup: self.recovered_from_backup,
            recovery_message: self.recovery_message.clone(),
            wal_recovered: self.wal_recovered,
            state_checksum: self.state_checksum.clone(),
        }
    }

    fn persist(&mut self) -> Result<(), CliError> {
        // CLI-FIND-RACE-003: Serialize all writers behind a module-local lock,
        // then validate the expected write_version while still holding that lock.
        // This closes the read-then-write window that allowed two stale writers to
        // both pass CAS validation before either write landed.
        std::fs::create_dir_all(&self.state_dir).map_err(|e| {
            CliError::internal(format!(
                "failed to create state dir {}: {e}",
                self.state_dir.display()
            ))
        })?;
        let _lock = acquire_state_file_lock(&self.lock_file)?;
        self.persist_locked()
    }

    fn persist_locked(&mut self) -> Result<(), CliError> {
        self.persist_locked_with_writer(|path, envelope, context| {
            atomic_write_json(path, envelope, context)
        })
    }

    fn persist_locked_with_writer<F>(&mut self, mut writer: F) -> Result<(), CliError>
    where
        F: FnMut(&Path, &PersistedSupervisorEnvelope, &str) -> Result<(), CliError>,
    {
        validate_expected_write_version(&self.state_file, self.loaded_write_version)?;
        self.persisted.schema_version = 1;
        self.persisted.updated_at = Utc::now().to_rfc3339();
        // Advance write_version monotonically from the last committed version we
        // loaded or wrote ourselves.
        self.persisted.write_version = self.loaded_write_version + 1;

        let payload_bytes = serde_json::to_vec(&self.persisted).map_err(|e| {
            CliError::internal(format!("failed to serialize supervisor state: {e}"))
        })?;
        let checksum = sha256_hex(&payload_bytes);
        let envelope = PersistedSupervisorEnvelope {
            schema_version: 1,
            updated_at: self.persisted.updated_at.clone(),
            checksum_sha256: checksum.clone(),
            payload: self.persisted.clone(),
        };
        writer(&self.state_file, &envelope, "supervisor state")?;
        let backup_refresh_error =
            writer(&self.backup_file, &envelope, "supervisor backup state").err();
        self.recovered_from_backup = false;
        self.recovery_message = None;
        self.state_checksum = Some(checksum);
        // Update loaded_write_version to track our own last successful write.
        self.loaded_write_version = self.persisted.write_version;
        if let Some(error) = backup_refresh_error {
            tracing::warn!(
                path = %self.backup_file.display(),
                error = %error,
                "supervisor state persisted but backup refresh failed; primary state remains authoritative"
            );
        }
        Ok(())
    }
}

struct StateFileLock {
    path: PathBuf,
    file: File,
}

impl Drop for StateFileLock {
    fn drop(&mut self) {
        if let Err(error) = self.file.unlock() {
            tracing::warn!(
                path = %self.path.display(),
                error = %error,
                "failed to release supervisor state lock"
            );
        }
    }
}

fn acquire_state_file_lock(lock_file: &Path) -> Result<StateFileLock, CliError> {
    let deadline = Instant::now() + Duration::from_secs(LOCK_TIMEOUT_SECS);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_file)
        .map_err(|error| {
            CliError::internal(format!(
                "failed to open supervisor state lock {}: {error}",
                lock_file.display()
            ))
        })?;

    loop {
        match file.try_lock_exclusive() {
            Ok(()) => {
                return Ok(StateFileLock {
                    path: lock_file.to_path_buf(),
                    file,
                });
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(CliError::internal(format!(
                        "timed out waiting for supervisor state lock {} after {}s; \
                         another process may be stuck persisting state",
                        lock_file.display(),
                        LOCK_TIMEOUT_SECS
                    )));
                }
                thread::sleep(Duration::from_millis(LOCK_RETRY_DELAY_MS));
            }
            Err(error) => {
                return Err(CliError::internal(format!(
                    "failed to acquire supervisor state lock {}: {error}",
                    lock_file.display()
                )));
            }
        }
    }
}

fn validate_expected_write_version(
    state_file: &Path,
    expected_write_version: u64,
) -> Result<(), CliError> {
    match read_current_write_version(state_file)? {
        Some(on_disk_write_version) if on_disk_write_version == expected_write_version => Ok(()),
        Some(on_disk_write_version) => Err(CliError::internal(format!(
            "supervisor state CAS conflict: on-disk write_version {} != loaded {}; \
             another process modified the state — reload and retry",
            on_disk_write_version, expected_write_version
        ))),
        None if expected_write_version == 0 => Ok(()),
        None => Err(CliError::internal(format!(
            "supervisor state CAS conflict: state file {} disappeared after loading write_version {}; \
             another process modified the state — reload and retry",
            state_file.display(),
            expected_write_version
        ))),
    }
}

fn read_current_write_version(state_file: &Path) -> Result<Option<u64>, CliError> {
    if !state_file.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(state_file).map_err(|error| {
        CliError::internal(format!(
            "failed to read supervisor state {} during CAS validation: {error}",
            state_file.display()
        ))
    })?;
    let (persisted, _) = decode_state_bytes(&bytes)?;
    Ok(Some(persisted.write_version))
}

fn decode_state_bytes(
    bytes: &[u8],
) -> Result<(PersistedSupervisorState, Option<String>), CliError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| CliError::internal(error.to_string()))?;

    reject_deprecated_rollout_history(&value)?;

    if let Ok(envelope) = serde_json::from_value::<PersistedSupervisorEnvelope>(value.clone()) {
        let payload_bytes = serde_json::to_vec(&envelope.payload).map_err(|error| {
            CliError::internal(format!(
                "failed to serialize supervisor payload for checksum: {error}"
            ))
        })?;
        let actual_checksum = sha256_hex(&payload_bytes);
        if actual_checksum != envelope.checksum_sha256 {
            return Err(CliError::internal(format!(
                "supervisor state checksum mismatch: expected {}, got {}",
                envelope.checksum_sha256, actual_checksum
            )));
        }
        return Ok((envelope.payload, Some(actual_checksum)));
    }

    serde_json::from_value::<PersistedSupervisorState>(value)
        .map(|payload| (payload, None))
        .map_err(|error| CliError::internal(error.to_string()))
}

fn reject_deprecated_rollout_history(value: &serde_json::Value) -> Result<(), CliError> {
    let instances = value
        .get("payload")
        .and_then(|payload| payload.get("instances"))
        .or_else(|| value.get("instances"))
        .and_then(|instances| instances.as_object());

    let Some(instances) = instances else {
        return Ok(());
    };

    for (instance_id, record) in instances {
        if record
            .as_object()
            .is_some_and(|record| record.contains_key("rollout_history"))
        {
            return Err(CliError::internal(format!(
                "deprecated rollout_history field found in supervisor state for instance {instance_id}; use operations_history"
            )));
        }
    }

    Ok(())
}

fn encode_state_envelope(
    persisted: &PersistedSupervisorState,
) -> Result<(PersistedSupervisorEnvelope, String), CliError> {
    let payload_bytes = serde_json::to_vec(persisted).map_err(|error| {
        CliError::internal(format!("failed to serialize supervisor state: {error}"))
    })?;
    let checksum = sha256_hex(&payload_bytes);
    Ok((
        PersistedSupervisorEnvelope {
            schema_version: 1,
            updated_at: persisted.updated_at.clone(),
            checksum_sha256: checksum.clone(),
            payload: persisted.clone(),
        },
        checksum,
    ))
}

fn load_backup_state(
    backup_file: &Path,
    primary_error: Option<&CliError>,
) -> Result<(PersistedSupervisorState, Option<String>), CliError> {
    let backup_bytes = std::fs::read(backup_file).map_err(|e| {
        CliError::internal(format!(
            "failed to read supervisor backup {}: {e}",
            backup_file.display()
        ))
    })?;
    decode_state_bytes(&backup_bytes).map_err(|backup_error| {
        if let Some(primary_error) = primary_error {
            CliError::internal(format!(
                "invalid supervisor state recovery: primary failed with {}; backup {} also invalid: {}",
                nested_cli_error_message(primary_error),
                backup_file.display(),
                nested_cli_error_message(&backup_error)
            ))
        } else {
            CliError::internal(format!(
                "invalid supervisor backup {}: {}",
                backup_file.display(),
                nested_cli_error_message(&backup_error)
            ))
        }
    })
}

fn nested_cli_error_message(error: &CliError) -> String {
    let rendered = error.to_string();
    rendered
        .split_once(": ")
        .map(|(_, message)| message.to_string())
        .unwrap_or(rendered)
}

fn repair_state_from_backup(
    state_file: &Path,
    backup_file: &Path,
    persisted: &PersistedSupervisorState,
) -> Result<(), CliError> {
    let (envelope, _) = encode_state_envelope(persisted)?;
    atomic_write_json(state_file, &envelope, "supervisor state repair")?;
    atomic_write_json(backup_file, &envelope, "supervisor backup repair")
}

fn repair_backup_from_primary_if_needed(
    backup_file: &Path,
    persisted: &PersistedSupervisorState,
) -> Result<(), CliError> {
    let backup_is_valid = if backup_file.exists() {
        match std::fs::read(backup_file) {
            Ok(bytes) => decode_state_bytes(&bytes).is_ok(),
            Err(_) => false,
        }
    } else {
        false
    };

    if backup_is_valid {
        return Ok(());
    }

    let (envelope, _) = encode_state_envelope(persisted)?;
    atomic_write_json(backup_file, &envelope, "supervisor backup repair")
}

fn read_wal_entries_from_path(path: &Path) -> Vec<WalEntry> {
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// CLI-FIND-LOW-003: Replay committed WAL entries idempotently.
///
/// Only committed entries are replayed (uncommitted entries represent incomplete
/// operations and are discarded). Replay is idempotent: re-applying a status
/// update or checkpoint that already exists produces the same state.
fn replay_committed_wal_entries(state: &mut PersistedSupervisorState, entries: &[WalEntry]) {
    for entry in entries {
        if !entry.committed {
            tracing::debug!(
                operation = entry.operation.as_str(),
                instance_id = entry.instance_id.as_deref().unwrap_or("<none>"),
                "WAL: discarding uncommitted entry"
            );
            continue;
        }

        tracing::info!(
            operation = entry.operation.as_str(),
            instance_id = entry.instance_id.as_deref().unwrap_or("<none>"),
            "WAL: replaying committed entry"
        );

        match entry.operation.as_str() {
            "set_status" => {
                if let Some(instance_id) = &entry.instance_id {
                    if let Some(record) = state.instances.get_mut(instance_id.as_str()) {
                        if let Ok(status) =
                            serde_json::from_value::<GatewayInstanceStatus>(entry.payload.clone())
                        {
                            record.status = status;
                        }
                    }
                }
            }
            "mark_action_applied" => {
                if let Some(instance_id) = &entry.instance_id {
                    if let Some(action_id) = entry.payload.as_str() {
                        state
                            .action_checkpoints
                            .entry(instance_id.clone())
                            .or_default()
                            .insert(action_id.to_string());
                    }
                }
            }
            "append_operation_history" => {
                if let Some(instance_id) = &entry.instance_id {
                    if let Some(record) = state.instances.get_mut(instance_id.as_str()) {
                        if let Ok(op_entry) =
                            serde_json::from_value::<OperationHistoryEntry>(entry.payload.clone())
                        {
                            // Idempotent: only append if not already present (check timestamp + action).
                            let already_present =
                                record.operations_history.iter().any(|existing| {
                                    existing.recorded_at == op_entry.recorded_at
                                        && existing.action == op_entry.action
                                });
                            if !already_present {
                                record.operations_history.push(op_entry);
                                if record.operations_history.len() > MAX_OPERATION_HISTORY_ENTRIES {
                                    let excess = record.operations_history.len()
                                        - MAX_OPERATION_HISTORY_ENTRIES;
                                    record.operations_history.drain(0..excess);
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                tracing::debug!(
                    operation = entry.operation.as_str(),
                    "WAL: unknown operation, skipping"
                );
            }
        }
    }

    state.updated_at = Utc::now().to_rfc3339();
}

pub fn default_state_dir() -> Result<PathBuf, CliError> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::user("HOME is not set"))?;
    Ok(home.join(".verdictan").join("supervisor"))
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
    use crate::instances::status::GatewayInstanceLifecycle;
    use crate::instances::{
        GatewayInstanceId, GatewayInstanceSpec, GatewayInstanceStatus, PolicyConfigSource,
    };

    fn sample_spec(instance_id: &str, port: u16) -> GatewayInstanceSpec {
        GatewayInstanceSpec::new(
            GatewayInstanceId::new(instance_id).unwrap(),
            instance_id,
            instance_id,
            &format!("127.0.0.1:{port}"),
            "https://api.openai.com",
            None,
            None,
            None,
            "block",
            PolicyConfigSource::path("/tmp/policy.yaml"),
            16,
            None,
            true,
        )
        .unwrap()
    }

    fn stage_instance(store: &mut SupervisorStateStore, spec: GatewayInstanceSpec) {
        let key = spec.instance_id.as_str().to_string();
        store.persisted.instances.insert(
            key,
            InstanceRecord {
                spec,
                status: GatewayInstanceStatus::default(),
                operations_history: Vec::new(),
                rollout_plan: None,
            },
        );
    }

    #[test]
    fn primary_state_commit_survives_backup_refresh_failure() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();

        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        stage_instance(&mut store, sample_spec("alpha", 41001));

        let mut backup_write_attempted = false;
        store
            .persist_locked_with_writer(|path, envelope, context| {
                if path.file_name().and_then(|value| value.to_str()) == Some(BACKUP_STATE_FILE_NAME)
                {
                    backup_write_attempted = true;
                    return Err(CliError::internal("simulated backup refresh failure"));
                }
                super::atomic_write_json(path, envelope, context)
            })
            .unwrap();

        assert!(backup_write_attempted);
        assert_eq!(store.loaded_write_version, 1);

        let reloaded = SupervisorStateStore::load(dir.path()).unwrap();
        assert_eq!(reloaded.list_instances().len(), 1);
        assert!(reloaded.get_instance("alpha").is_some());
        assert_eq!(reloaded.loaded_write_version, 1);
    }

    #[test]
    fn wal_replay_applies_committed_entries_and_discards_uncommitted() {
        let dir = tempfile::tempdir().unwrap();

        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store.create_instance(sample_spec("inst-1", 41010)).unwrap();

        let new_status =
            GatewayInstanceStatus::default().with_lifecycle(GatewayInstanceLifecycle::Running);
        let wal_entries = vec![
            WalEntry {
                operation: "set_status".to_string(),
                instance_id: Some("inst-1".to_string()),
                payload: serde_json::to_value(&new_status).unwrap(),
                timestamp: Utc::now().to_rfc3339(),
                committed: true,
            },
            WalEntry {
                operation: "mark_action_applied".to_string(),
                instance_id: Some("inst-1".to_string()),
                payload: serde_json::Value::String("action-wal-1".to_string()),
                timestamp: Utc::now().to_rfc3339(),
                committed: true,
            },
            WalEntry {
                operation: "mark_action_applied".to_string(),
                instance_id: Some("inst-1".to_string()),
                payload: serde_json::Value::String("should-be-dropped".to_string()),
                timestamp: Utc::now().to_rfc3339(),
                committed: false,
            },
        ];

        let wal_path = dir.path().join(WAL_FILE_NAME);
        let wal_bytes = serde_json::to_vec(&wal_entries).unwrap();
        std::fs::write(&wal_path, &wal_bytes).unwrap();

        let reloaded = SupervisorStateStore::load(dir.path()).unwrap();
        assert!(reloaded.wal_recovered);
        let inst = reloaded.get_instance("inst-1").unwrap();
        assert_eq!(inst.status.lifecycle, GatewayInstanceLifecycle::Running);
        assert!(reloaded.is_action_applied("inst-1", "action-wal-1"));
        assert!(!reloaded.is_action_applied("inst-1", "should-be-dropped"));
        assert!(!wal_path.exists());
    }

    #[test]
    fn backup_recovery_when_primary_is_corrupted() {
        let dir = tempfile::tempdir().unwrap();

        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store
            .create_instance(sample_spec("inst-backup", 41020))
            .unwrap();
        drop(store);

        std::fs::write(dir.path().join(STATE_FILE_NAME), b"{{invalid json}}").unwrap();

        let recovered = SupervisorStateStore::load(dir.path()).unwrap();
        assert!(recovered.recovered_from_backup);
        assert!(recovered
            .recovery_message
            .as_ref()
            .unwrap()
            .contains("backup"));
        assert!(recovered.get_instance("inst-backup").is_some());
    }

    #[test]
    fn operation_history_truncates_at_max_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store
            .create_instance(sample_spec("inst-trunc", 41030))
            .unwrap();

        for i in 0..(MAX_OPERATION_HISTORY_ENTRIES + 10) {
            store
                .append_operation_history(
                    "inst-trunc",
                    OperationHistoryEntry {
                        action: OperationAction::Reload,
                        outcome: OperationOutcome::Succeeded,
                        reason: Some(format!("op-{i}")),
                        previous_version: None,
                        previous_sha256: None,
                        target_version: None,
                        target_sha256: None,
                        active_version: None,
                        active_sha256: None,
                        recorded_at: Utc::now().to_rfc3339(),
                    },
                )
                .unwrap();
        }

        let inst = store.get_instance("inst-trunc").unwrap();
        assert_eq!(inst.operations_history.len(), MAX_OPERATION_HISTORY_ENTRIES);
        let first_remaining = inst.operations_history.first().unwrap();
        assert_eq!(first_remaining.reason.as_deref(), Some("op-10"));
    }

    #[test]
    fn reject_deprecated_rollout_history_detects_legacy_field() {
        let legacy = serde_json::json!({
            "instances": {
                "inst-1": {
                    "rollout_history": [{"entry": "bad"}]
                }
            }
        });
        let err = reject_deprecated_rollout_history(&legacy).unwrap_err();
        assert!(err.to_string().contains("deprecated rollout_history"));
    }

    #[test]
    fn reject_deprecated_rollout_history_passes_clean_state() {
        let clean = serde_json::json!({
            "instances": {
                "inst-1": {
                    "spec": {},
                    "status": {}
                }
            }
        });
        assert!(reject_deprecated_rollout_history(&clean).is_ok());
    }

    #[test]
    fn decode_state_bytes_validates_checksum() {
        let persisted = PersistedSupervisorState {
            schema_version: 1,
            updated_at: Utc::now().to_rfc3339(),
            write_version: 0,
            instances: BTreeMap::new(),
            action_checkpoints: BTreeMap::new(),
        };
        let (envelope, _) = encode_state_envelope(&persisted).unwrap();
        let mut envelope_modified = serde_json::to_value(&envelope).unwrap();
        envelope_modified["checksum_sha256"] =
            serde_json::Value::String("bad-checksum".to_string());

        let bytes = serde_json::to_vec(&envelope_modified).unwrap();
        let err = decode_state_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn fresh_store_has_write_version_zero() {
        let dir = tempfile::tempdir().unwrap();
        let store = SupervisorStateStore::load(dir.path()).unwrap();
        assert_eq!(store.loaded_write_version, 0);
    }

    #[test]
    fn persist_advances_write_version() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        assert_eq!(store.loaded_write_version, 0);

        store.create_instance(sample_spec("v-test", 41040)).unwrap();
        assert_eq!(store.loaded_write_version, 1);

        store.mark_action_applied("v-test", "act-1").unwrap();
        assert_eq!(store.loaded_write_version, 2);
    }

    // ── Enum serde round-trips ────────────────────────────────────────────

    #[test]
    fn operation_action_serde_all_variants() {
        for (action, expected) in [
            (OperationAction::Reload, "\"reload\""),
            (OperationAction::Reconcile, "\"reconcile\""),
            (OperationAction::CancelReconcile, "\"cancel_reconcile\""),
            (OperationAction::Revert, "\"revert\""),
            (OperationAction::Install, "\"install\""),
            (OperationAction::Start, "\"start\""),
            (OperationAction::Stop, "\"stop\""),
            (OperationAction::Uninstall, "\"uninstall\""),
        ] {
            let json = serde_json::to_string(&action).unwrap();
            assert_eq!(json, expected, "OperationAction::{action:?}");
            let recovered: OperationAction = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, action);
        }
    }

    #[test]
    fn operation_outcome_serde_all_variants() {
        for (outcome, expected) in [
            (OperationOutcome::Succeeded, "\"succeeded\""),
            (OperationOutcome::RolledBack, "\"rolled_back\""),
            (OperationOutcome::Failed, "\"failed\""),
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            assert_eq!(json, expected);
            let recovered: OperationOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, outcome);
        }
    }

    #[test]
    fn rollout_strategy_serde_all_variants() {
        for (strategy, expected) in [
            (RolloutStrategy::AllAtOnce, "\"all_at_once\""),
            (RolloutStrategy::Canary, "\"canary\""),
            (RolloutStrategy::Batch, "\"batch\""),
        ] {
            let json = serde_json::to_string(&strategy).unwrap();
            assert_eq!(json, expected);
            let recovered: RolloutStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, strategy);
        }
    }

    #[test]
    fn wal_entry_serde_round_trip() {
        let entry = WalEntry {
            operation: "set_status".to_string(),
            instance_id: Some("inst-1".to_string()),
            payload: serde_json::json!({"lifecycle": "running"}),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            committed: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let recovered: WalEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.operation, "set_status");
        assert_eq!(recovered.instance_id.as_deref(), Some("inst-1"));
        assert!(recovered.committed);
    }

    #[test]
    fn operation_history_entry_serde_round_trip() {
        let entry = OperationHistoryEntry {
            action: OperationAction::Reload,
            outcome: OperationOutcome::Succeeded,
            reason: Some("config changed".to_string()),
            previous_version: Some("v1".to_string()),
            previous_sha256: Some("sha1".to_string()),
            target_version: Some("v2".to_string()),
            target_sha256: Some("sha2".to_string()),
            active_version: Some("v2".to_string()),
            active_sha256: Some("sha2".to_string()),
            recorded_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let recovered: OperationHistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.action, OperationAction::Reload);
        assert_eq!(recovered.outcome, OperationOutcome::Succeeded);
        assert_eq!(recovered.reason.as_deref(), Some("config changed"));
    }

    #[test]
    fn rollout_plan_serde_round_trip() {
        let plan = RolloutPlan {
            strategy: RolloutStrategy::Canary,
            target_percentage: 25,
            pause_on_error: true,
            completed_instances: vec!["inst-1".to_string()],
            failed_instances: vec![],
            started_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:01:00Z".to_string(),
        };
        let json = serde_json::to_string(&plan).unwrap();
        let recovered: RolloutPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.strategy, RolloutStrategy::Canary);
        assert_eq!(recovered.target_percentage, 25);
        assert!(recovered.pause_on_error);
        assert_eq!(recovered.completed_instances.len(), 1);
        assert!(recovered.failed_instances.is_empty());
    }

    #[test]
    fn metadata_captures_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = SupervisorStateStore::load(dir.path()).unwrap();
        let meta = store.metadata();
        assert!(!meta.recovered_from_backup);
        assert!(meta.recovery_message.is_none());
        assert!(!meta.wal_recovered);
    }

    #[test]
    fn create_instance_and_list() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        assert!(store.list_instances().is_empty());

        store.create_instance(sample_spec("my-gw", 42001)).unwrap();
        let instances = store.list_instances();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].instance_id, "my-gw");
    }

    #[test]
    fn create_and_get_instance() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store.create_instance(sample_spec("rm-gw", 42002)).unwrap();
        assert!(store.get_instance("rm-gw").is_some());
        assert!(store.get_instance("nonexistent").is_none());
    }

    #[test]
    fn set_status_on_instance() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store.create_instance(sample_spec("st-gw", 42003)).unwrap();

        let new_status =
            GatewayInstanceStatus::default().with_lifecycle(GatewayInstanceLifecycle::Running);
        store.set_status("st-gw", new_status).unwrap();

        let inst = store.get_instance("st-gw").unwrap();
        assert_eq!(inst.status.lifecycle, GatewayInstanceLifecycle::Running);
    }

    #[test]
    fn action_checkpoint_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store
            .create_instance(sample_spec("ckpt-gw", 42004))
            .unwrap();

        assert!(!store.is_action_applied("ckpt-gw", "action-1"));
        store.mark_action_applied("ckpt-gw", "action-1").unwrap();
        assert!(store.is_action_applied("ckpt-gw", "action-1"));
        assert!(!store.is_action_applied("ckpt-gw", "action-2"));
    }

    // ── duplicate instance creation ─────────────────────────────────────

    #[test]
    fn create_instance_rejects_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store.create_instance(sample_spec("dup-gw", 42005)).unwrap();
        assert!(store.create_instance(sample_spec("dup-gw", 42006)).is_err());
    }

    // ── set_status on nonexistent instance ──────────────────────────────

    #[test]
    fn set_status_nonexistent_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        let status = GatewayInstanceStatus::default();
        assert!(store.set_status("missing", status).is_err());
    }

    // ── append_operation_history ─────────────────────────────────────────

    #[test]
    fn append_operation_history_trims_excess() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store
            .create_instance(sample_spec("hist-gw", 42010))
            .unwrap();

        for i in 0..(MAX_OPERATION_HISTORY_ENTRIES + 5) {
            let entry = OperationHistoryEntry {
                action: OperationAction::Reload,
                outcome: OperationOutcome::Succeeded,
                reason: Some(format!("entry-{i}")),
                previous_version: None,
                previous_sha256: None,
                target_version: None,
                target_sha256: None,
                active_version: None,
                active_sha256: None,
                recorded_at: chrono::Utc::now().to_rfc3339(),
            };
            store.append_operation_history("hist-gw", entry).unwrap();
        }

        let record = store.get_instance("hist-gw").unwrap();
        assert_eq!(
            record.operations_history.len(),
            MAX_OPERATION_HISTORY_ENTRIES
        );
    }

    #[test]
    fn append_operation_history_nonexistent_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        let entry = OperationHistoryEntry {
            action: OperationAction::Start,
            outcome: OperationOutcome::Failed,
            reason: None,
            previous_version: None,
            previous_sha256: None,
            target_version: None,
            target_sha256: None,
            active_version: None,
            active_sha256: None,
            recorded_at: chrono::Utc::now().to_rfc3339(),
        };
        assert!(store
            .append_operation_history("nonexistent", entry)
            .is_err());
    }

    // ── set_rollout_plan ────────────────────────────────────────────────

    #[test]
    fn set_rollout_plan_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store
            .create_instance(sample_spec("roll-gw", 42011))
            .unwrap();

        let plan = RolloutPlan {
            strategy: RolloutStrategy::Batch,
            target_percentage: 50,
            pause_on_error: false,
            completed_instances: vec![],
            failed_instances: vec![],
            started_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        };
        store.set_rollout_plan("roll-gw", Some(plan)).unwrap();
        assert!(store
            .get_instance("roll-gw")
            .unwrap()
            .rollout_plan
            .is_some());

        store.set_rollout_plan("roll-gw", None).unwrap();
        assert!(store
            .get_instance("roll-gw")
            .unwrap()
            .rollout_plan
            .is_none());
    }

    #[test]
    fn set_rollout_plan_nonexistent_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        assert!(store.set_rollout_plan("missing", None).is_err());
    }

    // ── state_dir accessor ──────────────────────────────────────────────

    #[test]
    fn state_dir_returns_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = SupervisorStateStore::load(dir.path()).unwrap();
        assert_eq!(store.state_dir(), dir.path());
    }

    // ── WAL replay ──────────────────────────────────────────────────────

    #[test]
    fn replay_committed_wal_entries_applies_set_status() {
        let mut state = PersistedSupervisorState {
            schema_version: 1,
            updated_at: chrono::Utc::now().to_rfc3339(),
            write_version: 0,
            instances: BTreeMap::new(),
            action_checkpoints: BTreeMap::new(),
        };
        let spec = sample_spec("wal-gw", 42020);
        state.instances.insert(
            "wal-gw".to_string(),
            InstanceRecord {
                spec,
                status: GatewayInstanceStatus::default(),
                operations_history: Vec::new(),
                rollout_plan: None,
            },
        );

        let status =
            GatewayInstanceStatus::default().with_lifecycle(GatewayInstanceLifecycle::Running);
        let entries = vec![WalEntry {
            operation: "set_status".to_string(),
            instance_id: Some("wal-gw".to_string()),
            payload: serde_json::to_value(&status).unwrap(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            committed: true,
        }];
        replay_committed_wal_entries(&mut state, &entries);
        assert_eq!(
            state.instances["wal-gw"].status.lifecycle,
            GatewayInstanceLifecycle::Running
        );
    }

    #[test]
    fn replay_committed_wal_entries_skips_uncommitted() {
        let mut state = PersistedSupervisorState {
            schema_version: 1,
            updated_at: chrono::Utc::now().to_rfc3339(),
            write_version: 0,
            instances: BTreeMap::new(),
            action_checkpoints: BTreeMap::new(),
        };
        let entries = vec![WalEntry {
            operation: "mark_action_applied".to_string(),
            instance_id: Some("inst".to_string()),
            payload: serde_json::Value::String("action-1".to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            committed: false,
        }];
        replay_committed_wal_entries(&mut state, &entries);
        assert!(state.action_checkpoints.is_empty());
    }

    #[test]
    fn replay_committed_wal_mark_action_applied() {
        let mut state = PersistedSupervisorState {
            schema_version: 1,
            updated_at: chrono::Utc::now().to_rfc3339(),
            write_version: 0,
            instances: BTreeMap::new(),
            action_checkpoints: BTreeMap::new(),
        };
        let entries = vec![WalEntry {
            operation: "mark_action_applied".to_string(),
            instance_id: Some("inst".to_string()),
            payload: serde_json::Value::String("action-1".to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            committed: true,
        }];
        replay_committed_wal_entries(&mut state, &entries);
        assert!(state
            .action_checkpoints
            .get("inst")
            .unwrap()
            .contains("action-1"));
    }

    #[test]
    fn replay_committed_wal_unknown_operation_no_panic() {
        let mut state = PersistedSupervisorState {
            schema_version: 1,
            updated_at: chrono::Utc::now().to_rfc3339(),
            write_version: 0,
            instances: BTreeMap::new(),
            action_checkpoints: BTreeMap::new(),
        };
        let entries = vec![WalEntry {
            operation: "unknown_op".to_string(),
            instance_id: None,
            payload: serde_json::Value::Null,
            timestamp: chrono::Utc::now().to_rfc3339(),
            committed: true,
        }];
        replay_committed_wal_entries(&mut state, &entries);
    }

    // ── reject_deprecated_rollout_history ────────────────────────────────

    #[test]
    fn reject_deprecated_rollout_history_clean() {
        let value = serde_json::json!({
            "instances": {
                "gw-1": { "spec": {}, "status": {} }
            }
        });
        assert!(reject_deprecated_rollout_history(&value).is_ok());
    }

    #[test]
    fn reject_deprecated_rollout_history_detects() {
        let value = serde_json::json!({
            "instances": {
                "gw-1": { "spec": {}, "rollout_history": [] }
            }
        });
        assert!(reject_deprecated_rollout_history(&value).is_err());
    }

    // ── encode_state_envelope ───────────────────────────────────────────

    #[test]
    fn encode_state_envelope_produces_valid_checksum() {
        let state = PersistedSupervisorState {
            schema_version: 1,
            updated_at: "2025-01-01T00:00:00Z".to_string(),
            write_version: 1,
            instances: BTreeMap::new(),
            action_checkpoints: BTreeMap::new(),
        };
        let (envelope, checksum) = encode_state_envelope(&state).unwrap();
        assert_eq!(envelope.checksum_sha256, checksum);
        assert!(!checksum.is_empty());
    }

    // ── OperationAction serde ───────────────────────────────────────────

    #[test]
    fn operation_action_serde_roundtrip() {
        let actions = [
            OperationAction::Reload,
            OperationAction::Reconcile,
            OperationAction::CancelReconcile,
            OperationAction::Revert,
            OperationAction::Install,
            OperationAction::Start,
            OperationAction::Stop,
            OperationAction::Uninstall,
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let recovered: OperationAction = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, action);
        }
    }

    // ── OperationOutcome serde ──────────────────────────────────────────

    #[test]
    fn operation_outcome_serde_roundtrip() {
        let outcomes = [
            OperationOutcome::Succeeded,
            OperationOutcome::RolledBack,
            OperationOutcome::Failed,
        ];
        for outcome in outcomes {
            let json = serde_json::to_string(&outcome).unwrap();
            let recovered: OperationOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, outcome);
        }
    }

    // ── RolloutStrategy serde ───────────────────────────────────────────

    #[test]
    fn rollout_strategy_serde_roundtrip() {
        let strategies = [
            RolloutStrategy::AllAtOnce,
            RolloutStrategy::Canary,
            RolloutStrategy::Batch,
        ];
        for strategy in strategies {
            let json = serde_json::to_string(&strategy).unwrap();
            let recovered: RolloutStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, strategy);
        }
    }

    // ── WalEntry serde ──────────────────────────────────────────────────

    #[test]
    fn wal_entry_serde_roundtrip() {
        let entry = WalEntry {
            operation: "set_status".to_string(),
            instance_id: Some("gw-1".to_string()),
            payload: serde_json::json!({"lifecycle": "running"}),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            committed: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let recovered: WalEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.operation, "set_status");
        assert!(recovered.committed);
    }

    // ── read_wal_entries_from_path ───────────────────────────────────────

    #[test]
    fn read_wal_entries_from_nonexistent_path() {
        let entries =
            read_wal_entries_from_path(std::path::Path::new("/tmp/__nonexistent_wal_path__"));
        assert!(entries.is_empty());
    }

    // ── SupervisorStateMetadata ─────────────────────────────────────────

    #[test]
    fn supervisor_state_metadata_serializes() {
        let meta = SupervisorStateMetadata {
            state_dir: "/tmp/test".to_string(),
            recovered_from_backup: false,
            recovery_message: None,
            wal_recovered: false,
            state_checksum: Some("abc123".to_string()),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("abc123"));
    }

    // ── MAX_OPERATION_HISTORY_ENTRIES ────────────────────────────────────

    #[test]
    fn max_operation_history_entries_value() {
        assert_eq!(MAX_OPERATION_HISTORY_ENTRIES, 25);
    }

    // ── Constants ───────────────────────────────────────────────────────

    #[test]
    fn constants_are_reasonable() {
        assert_eq!(STATE_FILE_NAME, "supervisor-state.json");
        assert_eq!(BACKUP_STATE_FILE_NAME, "supervisor-state.json.bak");
        assert_eq!(WAL_FILE_NAME, "supervisor-state.wal");
    }

    // ── Backup recovery on load ─────────────────────────────────────────

    #[test]
    fn load_recovers_from_backup_when_primary_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store.create_instance(sample_spec("bak-gw", 42030)).unwrap();

        std::fs::remove_file(dir.path().join(STATE_FILE_NAME)).unwrap();

        let recovered = SupervisorStateStore::load(dir.path()).unwrap();
        assert!(recovered.metadata().recovered_from_backup);
        assert!(recovered.get_instance("bak-gw").is_some());
    }

    // ── InstanceSummary fields ──────────────────────────────────────────

    #[test]
    fn list_instances_returns_correct_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store.create_instance(sample_spec("sum-gw", 42040)).unwrap();

        let instances = store.list_instances();
        assert_eq!(instances.len(), 1);
        let inst = &instances[0];
        assert_eq!(inst.instance_id, "sum-gw");
        assert_eq!(inst.gateway_id, "sum-gw");
        assert_eq!(inst.name, "sum-gw");
    }

    // ── multiple instances ─────────────────────────────────────────────

    #[test]
    fn create_multiple_instances_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store.create_instance(sample_spec("gw-a", 42050)).unwrap();
        store.create_instance(sample_spec("gw-b", 42051)).unwrap();
        assert_eq!(store.list_instances().len(), 2);
    }

    #[test]
    fn duplicate_instance_id_fails_on_create() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SupervisorStateStore::load(dir.path()).unwrap();
        store.create_instance(sample_spec("dup-gw", 42060)).unwrap();
        let result = store.create_instance(sample_spec("dup-gw", 42061));
        assert!(result.is_err());
    }

    // ── persistence roundtrip ─────────────────────────────────────────

    #[test]
    fn store_persists_across_reloads() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = SupervisorStateStore::load(dir.path()).unwrap();
            store
                .create_instance(sample_spec("persist-gw", 42090))
                .unwrap();
        }
        let reloaded = SupervisorStateStore::load(dir.path()).unwrap();
        assert!(reloaded.get_instance("persist-gw").is_some());
    }

    // ── WAL entry ────────────────────────────────────────────────────

    #[test]
    fn wal_entry_default_not_committed() {
        let entry = WalEntry {
            operation: "noop".to_string(),
            instance_id: None,
            payload: serde_json::json!(null),
            timestamp: "t".to_string(),
            committed: false,
        };
        assert!(!entry.committed);
    }

    // ── SupervisorStateMetadata ──────────────────────────────────────

    #[test]
    fn supervisor_state_metadata_defaults() {
        let meta = SupervisorStateMetadata {
            state_dir: "/tmp/default".to_string(),
            recovered_from_backup: false,
            recovery_message: None,
            wal_recovered: false,
            state_checksum: None,
        };
        assert!(!meta.recovered_from_backup);
        assert!(!meta.wal_recovered);
        assert!(meta.state_checksum.is_none());
    }

    #[test]
    fn default_state_dir_uses_home_environment() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", home.path());

        let path = default_state_dir().unwrap();
        assert_eq!(path, home.path().join(".verdictan").join("supervisor"));

        std::env::remove_var("HOME");
    }

    #[test]
    fn default_state_dir_errors_when_home_is_missing() {
        let _guard = crate::test_support::env_lock().lock().unwrap();
        std::env::remove_var("HOME");

        let err = default_state_dir().unwrap_err();
        assert!(err.to_string().contains("HOME is not set"));
    }

    #[test]
    fn read_current_write_version_returns_none_for_missing_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let state_file = dir.path().join(STATE_FILE_NAME);

        let version = read_current_write_version(&state_file).unwrap();
        assert!(version.is_none());
    }

    #[test]
    fn load_backup_state_includes_primary_and_backup_failures() {
        let dir = tempfile::tempdir().unwrap();
        let backup_file = dir.path().join(BACKUP_STATE_FILE_NAME);
        std::fs::write(&backup_file, b"not-json").unwrap();

        let err = load_backup_state(
            &backup_file,
            Some(&CliError::internal("primary decode failed")),
        )
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("primary failed with primary decode failed"));
        assert!(err.to_string().contains(BACKUP_STATE_FILE_NAME));
    }
}
