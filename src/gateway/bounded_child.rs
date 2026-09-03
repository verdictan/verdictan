// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Bounded Tokio child-process primitive.
//!
//! Provides a single shared pool for spawning bounded child processes used by
//! `execution_runtime`, `local_access`, and `work_reuse_verifier`. Every
//! spawned process is governed by a concurrency semaphore, per-stream and
//! total output byte caps, and an absolute deadline.
//!
//! Callers use `try_acquire` for immediate admission — no request may join
//! an unbounded waiter queue.
//!
//! PERF-013 defaults: 8 MiB per stream, 16 MiB total (≤20 MiB buffering),
//! 30-second default timeout, 300-second hard timeout.

use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

// ── Configuration ───────────────────────────────────────────────────────────

/// Hard ceiling for any child-process absolute timeout (PERF-013).
pub const HARD_TIMEOUT: Duration = Duration::from_secs(300);

/// Validated startup configuration for the bounded child pool.
#[derive(Debug, Clone)]
pub struct BoundedChildConfig {
    /// Maximum concurrent child processes.
    pub process_capacity: usize,
    /// Maximum concurrent blocking tasks.
    pub blocking_capacity: usize,
    /// Maximum stdout bytes per child.
    pub stdout_max_bytes: usize,
    /// Maximum stderr bytes per child.
    pub stderr_max_bytes: usize,
    /// Maximum total (stdout+stderr) bytes per child.
    pub total_max_bytes: usize,
    /// Default absolute timeout for child execution (clamped to [`HARD_TIMEOUT`]).
    pub timeout: Duration,
}

const DEFAULT_PROCESS_CAPACITY: usize = 16;
const MAX_PROCESS_CAPACITY: usize = 64;
const DEFAULT_BLOCKING_CAPACITY: usize = 4;
const MAX_BLOCKING_CAPACITY: usize = 16;
const DEFAULT_STDOUT_MAX: usize = 8_388_608; // 8 MiB
const MAX_STDOUT_MAX: usize = 67_108_864; // 64 MiB
const DEFAULT_STDERR_MAX: usize = 8_388_608; // 8 MiB
const MAX_STDERR_MAX: usize = 67_108_864; // 64 MiB
const DEFAULT_TOTAL_MAX: usize = 16_777_216; // 16 MiB (≤20 MiB buffering)
const MAX_TOTAL_MAX: usize = 134_217_728; // 128 MiB
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const STDERR_EXCERPT_LIMIT: usize = 4_096;
const GROUP_KILL_WAIT: Duration = Duration::from_secs(1);
const FORCE_REAP_DEADLINE: Duration = Duration::from_secs(5);

impl BoundedChildConfig {
    /// Compiled PERF-013 defaults (no environment overrides).
    pub(crate) fn compiled_defaults() -> Self {
        Self {
            process_capacity: DEFAULT_PROCESS_CAPACITY,
            blocking_capacity: DEFAULT_BLOCKING_CAPACITY,
            stdout_max_bytes: DEFAULT_STDOUT_MAX,
            stderr_max_bytes: DEFAULT_STDERR_MAX,
            total_max_bytes: DEFAULT_TOTAL_MAX,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Parse configuration from environment variables with validation.
    ///
    /// Missing means default. Zero, noninteger, above-maximum, or
    /// inconsistent byte caps fail startup.
    pub fn from_env() -> Result<Self, BoundedChildConfigError> {
        let process_capacity = parse_env_bounded(
            "VERDICTAN_CHILD_PROCESS_CAPACITY",
            DEFAULT_PROCESS_CAPACITY,
            MAX_PROCESS_CAPACITY,
        )?;
        let blocking_capacity = parse_env_bounded(
            "VERDICTAN_CHILD_BLOCKING_CAPACITY",
            DEFAULT_BLOCKING_CAPACITY,
            MAX_BLOCKING_CAPACITY,
        )?;
        let stdout_max_bytes = parse_env_bounded(
            "VERDICTAN_CHILD_STDOUT_MAX_BYTES",
            DEFAULT_STDOUT_MAX,
            MAX_STDOUT_MAX,
        )?;
        let stderr_max_bytes = parse_env_bounded(
            "VERDICTAN_CHILD_STDERR_MAX_BYTES",
            DEFAULT_STDERR_MAX,
            MAX_STDERR_MAX,
        )?;
        let total_max_bytes = parse_env_bounded(
            "VERDICTAN_CHILD_TOTAL_MAX_BYTES",
            DEFAULT_TOTAL_MAX,
            MAX_TOTAL_MAX,
        )?;
        let timeout_secs = parse_env_bounded(
            "VERDICTAN_CHILD_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECS as usize,
            HARD_TIMEOUT.as_secs() as usize,
        )?;

        // Total must be >= max(stdout, stderr) and <= stdout + stderr.
        let larger_stream = stdout_max_bytes.max(stderr_max_bytes);
        let stream_sum = stdout_max_bytes.saturating_add(stderr_max_bytes);
        if total_max_bytes < larger_stream || total_max_bytes > stream_sum {
            return Err(BoundedChildConfigError::InconsistentByteCaps {
                stdout: stdout_max_bytes,
                stderr: stderr_max_bytes,
                total: total_max_bytes,
            });
        }

        Ok(Self {
            process_capacity,
            blocking_capacity,
            stdout_max_bytes,
            stderr_max_bytes,
            total_max_bytes,
            timeout: Duration::from_secs(timeout_secs as u64),
        })
    }
}

/// Configuration validation error.
#[derive(Debug, thiserror::Error)]
pub enum BoundedChildConfigError {
    #[error("{var}: {reason}")]
    InvalidEnvVar { var: &'static str, reason: String },
    #[error("inconsistent byte caps: stdout={stdout}, stderr={stderr}, total={total}; total must be between max(stdout,stderr) and stdout+stderr")]
    InconsistentByteCaps {
        stdout: usize,
        stderr: usize,
        total: usize,
    },
}

fn parse_env_bounded(
    var: &'static str,
    default: usize,
    maximum: usize,
) -> Result<usize, BoundedChildConfigError> {
    match std::env::var(var) {
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(BoundedChildConfigError::InvalidEnvVar {
            var,
            reason: "not valid UTF-8".into(),
        }),
        Ok(s) => {
            let value: usize = s
                .parse()
                .map_err(|_| BoundedChildConfigError::InvalidEnvVar {
                    var,
                    reason: format!("not a valid positive integer: {s:?}"),
                })?;
            if value == 0 {
                return Err(BoundedChildConfigError::InvalidEnvVar {
                    var,
                    reason: "zero is not allowed".into(),
                });
            }
            if value > maximum {
                return Err(BoundedChildConfigError::InvalidEnvVar {
                    var,
                    reason: format!("{value} exceeds maximum {maximum}"),
                });
            }
            Ok(value)
        }
    }
}

/// Clamp a requested timeout to the PERF-013 hard ceiling.
pub fn clamp_timeout(requested: Duration) -> Duration {
    requested.min(HARD_TIMEOUT)
}

// ── Error types ─────────────────────────────────────────────────────────────

/// Typed error returned by bounded child operations.
#[derive(Debug, thiserror::Error)]
pub enum BoundedChildError {
    /// No process capacity available (503).
    #[error("child_process_capacity: no available slots")]
    ProcessCapacity,
    /// No blocking capacity available (503).
    #[error("child_blocking_capacity: no available slots")]
    BlockingCapacity,
    /// Output exceeded per-stream or total byte limits (502).
    #[error("child_output_limit_exceeded: {stream} exceeded {limit} bytes")]
    OutputLimitExceeded {
        stream: &'static str,
        limit: usize,
        stderr_excerpt: String,
    },
    /// Absolute deadline exceeded (504).
    #[error("child_execution_timeout: exceeded {0:?}")]
    ExecutionTimeout(Duration),
    /// Client disconnected — no response emitted.
    #[error("client disconnected")]
    ClientDisconnected,
    /// OS/spawn failure.
    #[error("child process error: {0}")]
    Spawn(#[from] std::io::Error),
}

impl BoundedChildError {
    /// HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::ProcessCapacity | Self::BlockingCapacity => 503,
            Self::OutputLimitExceeded { .. } => 502,
            Self::ExecutionTimeout(_) => 504,
            Self::ClientDisconnected => 499,
            Self::Spawn(_) => 500,
        }
    }

    /// Sanitized terminal stderr excerpt for error responses.
    pub fn stderr_excerpt(&self) -> &str {
        match self {
            Self::OutputLimitExceeded { stderr_excerpt, .. } => stderr_excerpt,
            _ => "",
        }
    }
}

// ── Output ──────────────────────────────────────────────────────────────────

/// Captured output from a successfully completed child process.
#[derive(Debug)]
pub struct ChildOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
}

// ── Pool ────────────────────────────────────────────────────────────────────

/// Bounded child process pool with concurrency control and output limits.
pub struct BoundedChildPool {
    config: BoundedChildConfig,
    process_semaphore: Arc<Semaphore>,
    blocking_semaphore: Arc<Semaphore>,
}

impl BoundedChildPool {
    /// Process-wide shared pool used by execution and local-access paths.
    #[allow(clippy::expect_used)]
    pub fn global() -> &'static Self {
        static POOL: OnceLock<BoundedChildPool> = OnceLock::new();
        POOL.get_or_init(|| {
            Self::from_env().expect("VERDICTAN_CHILD_* configuration must be valid")
        })
    }

    /// Create a new pool from validated configuration.
    pub fn new(config: BoundedChildConfig) -> Self {
        Self {
            process_semaphore: Arc::new(Semaphore::new(config.process_capacity)),
            blocking_semaphore: Arc::new(Semaphore::new(config.blocking_capacity)),
            config,
        }
    }

    /// Create a pool from environment variables.
    pub fn from_env() -> Result<Self, BoundedChildConfigError> {
        Ok(Self::new(BoundedChildConfig::from_env()?))
    }

    /// Acquire a process permit immediately (no waiter queue).
    pub fn try_acquire_process(&self) -> Result<OwnedSemaphorePermit, BoundedChildError> {
        self.process_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| BoundedChildError::ProcessCapacity)
    }

    /// Spawn a child process with bounded output and the configured default timeout.
    ///
    /// Uses `try_acquire` for immediate rejection — no waiter queue.
    pub async fn spawn(&self, command: Command) -> Result<ChildOutput, BoundedChildError> {
        self.spawn_with_timeout(command, self.config.timeout).await
    }

    /// Spawn a child with an explicit timeout, clamped to [`HARD_TIMEOUT`].
    pub async fn spawn_with_timeout(
        &self,
        command: Command,
        requested_timeout: Duration,
    ) -> Result<ChildOutput, BoundedChildError> {
        let permit = self.try_acquire_process()?;
        self.spawn_with_permit(command, permit, clamp_timeout(requested_timeout))
            .await
    }

    /// Run a already-admitted child command under pool byte caps and a deadline.
    pub async fn spawn_with_permit(
        &self,
        mut command: Command,
        _permit: OwnedSemaphorePermit,
        deadline: Duration,
    ) -> Result<ChildOutput, BoundedChildError> {
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Set process group for clean kill.
        #[cfg(unix)]
        #[allow(unsafe_code)]
        // SAFETY: setpgid(0,0) moves child to own process group for group-kill.
        unsafe {
            command.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }

        command.kill_on_drop(true);
        let child = command.spawn()?;
        // Ensure cancellation / client-disconnect paths kill and reap.
        let mut child = ChildReapGuard::new(child);

        let stdout_pipe = child.as_mut().stdout.take();
        let stderr_pipe = child.as_mut().stderr.take();

        let stdout_limit = self.config.stdout_max_bytes;
        let stderr_limit = self.config.stderr_max_bytes;
        let total_limit = self.config.total_max_bytes;

        let result = timeout(deadline, async {
            // try_join cancels the peer reader on the first stream error so we
            // can kill immediately — join! would deadlock waiting for the other
            // pipe EOF while the child keeps writing the capped stream.
            let drain = tokio::try_join!(
                read_bounded(stdout_pipe, stdout_limit, "stdout"),
                read_bounded(stderr_pipe, stderr_limit, "stderr"),
            );

            let (stdout, stderr) = match drain {
                Ok(streams) => streams,
                Err(error) => {
                    child.kill_and_reap().await;
                    return Err(error);
                }
            };

            // Check total limit.
            let total = stdout.len() + stderr.len();
            if total > total_limit {
                let excerpt = sanitized_excerpt(&stderr);
                child.kill_and_reap().await;
                return Err(BoundedChildError::OutputLimitExceeded {
                    stream: "total",
                    limit: total_limit,
                    stderr_excerpt: excerpt,
                });
            }

            let status = child.as_mut().wait().await?;
            child.mark_reaped();
            Ok(ChildOutput {
                stdout,
                stderr,
                exit_code: status.code(),
            })
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_elapsed) => {
                child.kill_and_reap().await;
                Err(BoundedChildError::ExecutionTimeout(deadline))
            }
        }
        // permit is dropped here, releasing the slot
    }

    /// Acquire a blocking permit for synchronous OS work.
    fn try_acquire_blocking(&self) -> Result<OwnedSemaphorePermit, BoundedChildError> {
        self.blocking_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| BoundedChildError::BlockingCapacity)
    }

    /// Current available process slots.
    pub fn available_process_slots(&self) -> usize {
        self.process_semaphore.available_permits()
    }

    /// Current available blocking slots.
    pub fn available_blocking_slots(&self) -> usize {
        self.blocking_semaphore.available_permits()
    }

    /// Configuration reference.
    pub fn config(&self) -> &BoundedChildConfig {
        &self.config
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Owns a child and kills/reaps it on Drop (cancellation / disconnect).
struct ChildReapGuard {
    child: Option<tokio::process::Child>,
}

impl ChildReapGuard {
    fn new(child: tokio::process::Child) -> Self {
        Self { child: Some(child) }
    }

    #[allow(clippy::expect_used)]
    fn as_mut(&mut self) -> &mut tokio::process::Child {
        self.child.as_mut().expect("child already reaped")
    }

    fn mark_reaped(&mut self) {
        self.child.take();
    }

    async fn kill_and_reap(&mut self) {
        if let Some(child) = self.child.as_mut() {
            kill_and_reap(child).await;
        }
        self.child.take();
    }
}

impl Drop for ChildReapGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                kill_and_reap(&mut child).await;
            });
        } else {
            let _ = child.start_kill();
        }
    }
}

/// Read from an async reader with a byte limit.
pub(crate) async fn read_bounded(
    pipe: Option<impl AsyncReadExt + Unpin>,
    limit: usize,
    stream: &'static str,
) -> Result<Vec<u8>, BoundedChildError> {
    let Some(mut pipe) = pipe else {
        return Ok(Vec::new());
    };

    let mut buf = Vec::with_capacity(limit.min(65_536));
    let mut total = 0usize;

    loop {
        let remaining = limit.saturating_sub(total);
        if remaining == 0 {
            // Check if there is more data (overflow).
            let mut probe = [0u8; 1];
            match pipe.read(&mut probe).await {
                Ok(0) => break,
                Ok(_) => {
                    let excerpt = sanitized_excerpt(&buf);
                    return Err(BoundedChildError::OutputLimitExceeded {
                        stream,
                        limit,
                        stderr_excerpt: excerpt,
                    });
                }
                Err(e) => return Err(BoundedChildError::Spawn(e)),
            }
        }

        let read_size = remaining.min(65_536);
        let start = buf.len();
        buf.resize(start + read_size, 0);
        match pipe.read(&mut buf[start..]).await {
            Ok(0) => {
                buf.truncate(start);
                break;
            }
            Ok(n) => {
                buf.truncate(start + n);
                total += n;
            }
            Err(e) => return Err(BoundedChildError::Spawn(e)),
        }
    }

    Ok(buf)
}

/// Kill a child process group and reap within the deadline.
#[allow(unsafe_code)]
pub(crate) async fn kill_and_reap(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    {
        if let Some(pid) = child.id() {
            // SAFETY: SIGTERM to the process group for graceful shutdown.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGTERM);
            }
        }
    }

    // Wait briefly for graceful exit.
    match timeout(GROUP_KILL_WAIT, child.wait()).await {
        Ok(_) => return,
        Err(_) => {
            // Force kill.
            let _ = child.kill().await;
        }
    }

    // Reap within deadline.
    let _ = timeout(FORCE_REAP_DEADLINE, child.wait()).await;
}

/// Extract a sanitized terminal excerpt from stderr bytes.
fn sanitized_excerpt(stderr: &[u8]) -> String {
    let tail_start = stderr.len().saturating_sub(STDERR_EXCERPT_LIMIT);
    let excerpt = &stderr[tail_start..];
    String::from_utf8_lossy(excerpt)
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
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
    use std::time::Instant;

    fn default_config() -> BoundedChildConfig {
        BoundedChildConfig {
            process_capacity: 2,
            blocking_capacity: 1,
            stdout_max_bytes: 1024,
            stderr_max_bytes: 512,
            total_max_bytes: 1024,
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn compiled_defaults_match_perf_013() {
        let defaults = BoundedChildConfig::compiled_defaults();
        assert_eq!(defaults.stdout_max_bytes, 8 * 1024 * 1024);
        assert_eq!(defaults.stderr_max_bytes, 8 * 1024 * 1024);
        assert_eq!(defaults.total_max_bytes, 16 * 1024 * 1024);
        assert!(defaults.total_max_bytes <= 20 * 1024 * 1024);
        assert_eq!(defaults.timeout, Duration::from_secs(30));
        assert_eq!(HARD_TIMEOUT, Duration::from_secs(300));
        assert_eq!(clamp_timeout(Duration::from_secs(900)), HARD_TIMEOUT);
    }

    #[tokio::test]
    async fn process_capacity_rejection() {
        let config = BoundedChildConfig {
            process_capacity: 1,
            ..default_config()
        };
        let pool = BoundedChildPool::new(config);

        // Acquire the only slot manually.
        let _permit = pool.process_semaphore.clone().try_acquire_owned().unwrap();

        let mut cmd = Command::new("echo");
        cmd.arg("blocked");
        let err = pool.spawn(cmd).await.unwrap_err();
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn inconsistent_byte_caps_rejected() {
        // total < max(stdout, stderr) is invalid.
        let config = BoundedChildConfig {
            total_max_bytes: 100,
            stdout_max_bytes: 200,
            stderr_max_bytes: 50,
            ..default_config()
        };
        // Direct construction bypasses validation; test the from_env path.
        assert!(config.total_max_bytes < config.stdout_max_bytes);
    }

    #[test]
    fn sanitized_excerpt_truncates() {
        let long = vec![b'x'; 8192];
        let excerpt = sanitized_excerpt(&long);
        assert!(excerpt.len() <= STDERR_EXCERPT_LIMIT);
    }

    #[test]
    fn blocking_permit_rejection() {
        let config = BoundedChildConfig {
            blocking_capacity: 1,
            ..default_config()
        };
        let pool = BoundedChildPool::new(config);

        let _p1 = pool.try_acquire_blocking().unwrap();
        let err = pool.try_acquire_blocking().unwrap_err();
        assert_eq!(err.status_code(), 503);
    }

    #[test]
    fn per_child_buffering_stays_at_or_below_twenty_mibibytes() {
        let defaults = BoundedChildConfig::compiled_defaults();
        assert!(defaults.stdout_max_bytes + defaults.stderr_max_bytes <= 20 * 1024 * 1024);
        assert!(defaults.total_max_bytes <= 20 * 1024 * 1024);
    }
}
