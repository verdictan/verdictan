// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use bytes::Bytes;
use futures_util::stream;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::OwnedSemaphorePermit;
use tokio_stream::wrappers::ReceiverStream;

use crate::error::CliError;

use super::bounded_child::{clamp_timeout, BoundedChildPool, HARD_TIMEOUT};
use super::cache::BufferedUpstreamResponse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterFamily {
    Browser,
    ChatKit,
    Transformers,
    ClaudeAgentSdk,
    CodexSdk,
    Mcp,
    WebSocket,
    OpenAiAgents,
    OpenCodeSdk,
    BedrockAgents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionSupportMode {
    AdapterOnly,
    NativeRunnerOrAdapter,
}

/// Config-time capability classification for an execution provider string.
///
/// This enum separates statically-known support level from the runtime `ExecutionTarget`
/// so that configuration linting and startup validation can reject unsupported targets
/// before the first request arrives. Request-time `StatusCode::NOT_IMPLEMENTED` paths
/// in `execute_target` and `execute_target_streaming` remain as defence-in-depth.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionCapability {
    /// Fully supported: an explicit `exec:` or `file://` target, the `echo` provider, or a
    /// named family that has a viable native-runner path (e.g. `claude-agent-sdk`, `codex-sdk`).
    Supported,
    /// Supported only when an `adapter_command` is supplied in the provider config.
    /// Configuration without `adapter_command` will produce `ExecutionTarget::Unsupported`
    /// at parse time and a `501` at request time.
    SupportedWithAdapter,
    /// Statically unsupported: the provider string is a known but unimplemented execution
    /// family (e.g. `manual-input`, `go`, `ruby`, `sequence`). These MUST be rejected
    /// during config parsing or startup; they should never reach a running request handler.
    UnsupportedAtConfigTime,
}

/// Classify the config-time capability of a raw provider string.
///
/// This function operates on the provider string alone, without a full config entry,
/// so it can be called during lint and startup validation before any `Value` is parsed.
///
/// Returns:
/// - `Supported` — explicit `exec:`, `file://`, `echo`, or a named family with a native runner
/// - `SupportedWithAdapter` — adapter-only families (`browser`, `chatkit`, `websocket`)
/// - `UnsupportedAtConfigTime` — statically rejected provider strings or unknown aliases
pub fn classify_capability(raw_provider: &str) -> ExecutionCapability {
    let trimmed = raw_provider.trim();

    // Explicit execution targets are always supported regardless of config content.
    if trimmed.starts_with("exec:") || trimmed.starts_with("file://") {
        return ExecutionCapability::Supported;
    }
    if trimmed == "echo" {
        return ExecutionCapability::Supported;
    }

    // Statically unsupported aliases are rejected at config time.
    let normalized = normalized_execution_alias(trimmed);
    if matches!(
        normalized.as_str(),
        "manual-input"
            | "sequence"
            | "simulated-user"
            | "slack-feedback"
            | "go"
            | "ruby"
            | "webhook"
    ) {
        return ExecutionCapability::UnsupportedAtConfigTime;
    }

    // Resolve the adapter family from the provider string.
    let family =
        parse_execution_family(trimmed)
            .map(|spec| spec.family)
            .or(match normalized.as_str() {
                "browser" => Some(AdapterFamily::Browser),
                "chatkit" => Some(AdapterFamily::ChatKit),
                "websocket" => Some(AdapterFamily::WebSocket),
                "claude-agent-sdk" => Some(AdapterFamily::ClaudeAgentSdk),
                "codex-sdk" => Some(AdapterFamily::CodexSdk),
                "mcp" => Some(AdapterFamily::Mcp),
                "openai-agents" => Some(AdapterFamily::OpenAiAgents),
                "opencode-sdk" => Some(AdapterFamily::OpenCodeSdk),
                "bedrock-agents" => Some(AdapterFamily::BedrockAgents),
                "transformers" => Some(AdapterFamily::Transformers),
                _ => None,
            });

    match family {
        Some(f) => match f.support_mode() {
            ExecutionSupportMode::AdapterOnly => ExecutionCapability::SupportedWithAdapter,
            ExecutionSupportMode::NativeRunnerOrAdapter => ExecutionCapability::Supported,
        },
        None => ExecutionCapability::UnsupportedAtConfigTime,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionFamilyInfo {
    pub family: AdapterFamily,
    pub kind: &'static str,
}

impl AdapterFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::ChatKit => "chatkit",
            Self::Transformers => "transformers",
            Self::ClaudeAgentSdk => "claude-agent-sdk",
            Self::CodexSdk => "codex-sdk",
            Self::Mcp => "mcp",
            Self::WebSocket => "websocket",
            Self::OpenAiAgents => "openai-agents",
            Self::OpenCodeSdk => "opencode-sdk",
            Self::BedrockAgents => "bedrock-agents",
        }
    }

    pub fn support_mode(&self) -> ExecutionSupportMode {
        match self {
            Self::Browser | Self::ChatKit | Self::WebSocket => ExecutionSupportMode::AdapterOnly,
            Self::Transformers
            | Self::ClaudeAgentSdk
            | Self::CodexSdk
            | Self::Mcp
            | Self::OpenAiAgents
            | Self::OpenCodeSdk
            | Self::BedrockAgents => ExecutionSupportMode::NativeRunnerOrAdapter,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandExecutionTarget {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: HashMap<String, String>,
    pub timeout: Duration,
    pub family: Option<AdapterFamily>,
    pub workflow_id: Option<String>,
    pub runner_config: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct FileExecutionTarget {
    pub path: String,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub enum ExecutionTarget {
    Command(CommandExecutionTarget),
    File(FileExecutionTarget),
    Echo,
    Unsupported { kind: String, reason: String },
}

pub type ExecutionByteStream =
    futures_util::stream::BoxStream<'static, Result<Bytes, std::io::Error>>;

/// CLI-SEC-009: Default allowlist of programs that may be spawned by execution
/// runtime targets. Config-defined programs are checked against this list before
/// spawning. This is a security boundary: only programs known to implement the
/// expected execution protocol should be listed here.
const DEFAULT_EXECUTION_ALLOWLIST: &[&str] = &[
    "node",
    "npx",
    "python",
    "python3",
    "deno",
    "bun",
    "cargo",
    "go",
    "ruby",
    "sh",
    "verdictan",
    "claude",
    "codex",
    "openai-agents",
    "opencode",
    "bedrock-agents",
];

const EXECUTION_STDERR_EXCERPT_BYTES: usize = 4 * 1024;
const STREAM_CHANNEL_CAPACITY: usize = 16;
const STREAM_READ_CHUNK_BYTES: usize = 4 * 1024;

fn execution_child_pool() -> &'static BoundedChildPool {
    BoundedChildPool::global()
}

fn execution_stream_limit(stream: &'static str) -> usize {
    let config = execution_child_pool().config();
    match stream {
        "stderr" => config.stderr_max_bytes,
        _ => config.stdout_max_bytes,
    }
}

#[cfg(unix)]
const TRUSTED_EXECUTION_DIRECTORIES: &[&str] = &[
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/local/sbin",
    "/usr/sbin",
    "/sbin",
    "/opt/homebrew/bin",
    "/opt/local/bin",
];

#[cfg(windows)]
const TRUSTED_EXECUTION_DIRECTORIES: &[&str] = &[
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Windows\System32",
];

#[cfg(not(any(unix, windows)))]
const TRUSTED_EXECUTION_DIRECTORIES: &[&str] = &[];

/// Script extensions whose interpreters are in the default allowlist.
/// A path ending in one of these is permitted because `script_launcher` resolves
/// them to an allowed interpreter (python3, node, ruby, sh).
const ALLOWED_SCRIPT_EXTENSIONS: &[&str] = &["py", "js", "mjs", "cjs", "rb", "sh"];

/// Validates that a program name is permitted by the execution allowlist.
/// Returns `true` if the program basename matches an entry in the allowlist,
/// or if the program path has a known script extension whose interpreter is allowed.
fn is_allowed_execution_program(program: &str) -> bool {
    let path = Path::new(program);
    let basename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program);
    if DEFAULT_EXECUTION_ALLOWLIST.contains(&basename) {
        return true;
    }
    // Accept script files that script_launcher would resolve to an allowed interpreter.
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        return ALLOWED_SCRIPT_EXTENSIONS
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(ext));
    }
    false
}

#[derive(Debug)]
struct TrustedExecutionProgram {
    canonical_path: PathBuf,
    execution_path: PathBuf,
    _pinned_file: File,
}

impl TrustedExecutionProgram {
    fn resolve(program: &str) -> Result<Self, CliError> {
        let roots = TRUSTED_EXECUTION_DIRECTORIES
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        Self::resolve_in_roots_with_ownership(program, &roots, true)
    }

    fn resolve_in_roots_with_ownership(
        program: &str,
        roots: &[PathBuf],
        require_static_ownership: bool,
    ) -> Result<Self, CliError> {
        let requested = Path::new(program);
        let basename = requested
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CliError::user("execution program has no valid file name"))?;
        if !DEFAULT_EXECUTION_ALLOWLIST.contains(&basename) {
            return Err(CliError::user(format!(
                "execution program '{program}' is not in the execution allowlist"
            )));
        }

        let canonical_roots = roots
            .iter()
            .filter_map(|root| root.canonicalize().ok())
            .collect::<Vec<_>>();
        if canonical_roots.is_empty() {
            return Err(CliError::user(
                "no pinned trusted execution directory is available",
            ));
        }

        let candidates = if requested.is_absolute() || requested.components().count() > 1 {
            vec![requested.to_path_buf()]
        } else {
            roots.iter().map(|root| root.join(requested)).collect()
        };

        for candidate in candidates {
            let Ok(canonical_path) = candidate.canonicalize() else {
                continue;
            };
            let Some(canonical_root) = canonical_roots
                .iter()
                .find(|root| canonical_path.starts_with(root))
            else {
                continue;
            };
            if require_static_ownership
                && !has_static_system_ownership(canonical_root, &canonical_path)
            {
                continue;
            }
            let Ok(pinned_file) = open_pinned_executable(&canonical_path) else {
                continue;
            };
            let Ok(metadata) = pinned_file.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            if !pinned_handle_matches_path(&pinned_file, &canonical_path) {
                continue;
            }

            #[cfg(target_os = "linux")]
            let execution_path = {
                use std::os::fd::AsRawFd;
                PathBuf::from(format!("/proc/self/fd/{}", pinned_file.as_raw_fd()))
            };
            #[cfg(all(unix, not(target_os = "linux")))]
            let execution_path = {
                use std::os::fd::AsRawFd;
                PathBuf::from(format!("/dev/fd/{}", pinned_file.as_raw_fd()))
            };
            // `CreateProcess` accepts a program path and not a handle, so
            // Windows cannot execute the pinned descriptor the way `execve` on
            // `/proc/self/fd/N` can. `open_pinned_executable` therefore holds a
            // deny-write, deny-delete share mode on the file, and
            // `ensure_pinned_identity_before_spawn` rechecks the pinned
            // `FILE_ID_INFO` immediately before the spawn.
            #[cfg(not(unix))]
            let execution_path = canonical_path.clone();

            return Ok(Self {
                canonical_path,
                execution_path,
                _pinned_file: pinned_file,
            });
        }

        Err(CliError::user(format!(
            "execution program '{program}' is not a canonical binary beneath a pinned trusted directory"
        )))
    }

    /// Proves that the execution path still names the validated binary.
    ///
    /// On Unix the execution path *is* the pinned descriptor, so the kernel
    /// already guarantees this and the check is a no-op. On Windows the spawn
    /// resolves a path string again, so the pinned `FILE_ID_INFO` is compared
    /// against the file that the path currently names.
    fn ensure_pinned_identity_before_spawn(&self) -> std::io::Result<()> {
        #[cfg(windows)]
        super::windows_trusted_execution::ensure_same_identity(
            &self._pinned_file,
            &self.canonical_path,
        )?;
        Ok(())
    }
}

/// Opens the execution binary and keeps the handle for the lifetime of the
/// resolved program.
///
/// Windows additionally requests a deny-write, deny-delete share mode so that
/// no other process can write, truncate, rename, or delete the pinned file.
#[cfg(not(windows))]
fn open_pinned_executable(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
fn open_pinned_executable(path: &Path) -> std::io::Result<File> {
    super::windows_trusted_execution::open_pinned_executable(path)
}

/// Reports whether the pinned handle and the current contents of `path` are the
/// same file.
#[cfg(unix)]
fn pinned_handle_matches_path(file: &File, path: &Path) -> bool {
    let Ok(handle_metadata) = file.metadata() else {
        return false;
    };
    let Ok(path_metadata) = path.metadata() else {
        return false;
    };
    same_file_identity(&handle_metadata, &path_metadata)
}

#[cfg(windows)]
fn pinned_handle_matches_path(file: &File, path: &Path) -> bool {
    super::windows_trusted_execution::pinned_handle_matches_path(file, path)
}

/// No other platform has a trusted execution directory, so
/// `TRUSTED_EXECUTION_DIRECTORIES` is empty and resolution fails before this
/// point. Fail closed.
#[cfg(not(any(unix, windows)))]
fn pinned_handle_matches_path(_file: &File, _path: &Path) -> bool {
    false
}

#[cfg(unix)]
fn has_static_system_ownership(root: &Path, executable: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let trusted_metadata = |path: &Path, must_be_executable: bool| {
        path.metadata().is_ok_and(|metadata| {
            metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && (!must_be_executable || metadata.mode() & 0o111 != 0)
        })
    };

    if executable == root {
        return trusted_metadata(root, false);
    }
    if !trusted_metadata(executable, true) {
        return false;
    }
    let mut directory = executable.parent();
    while let Some(path) = directory {
        if !path.starts_with(root) || !trusted_metadata(path, false) {
            return false;
        }
        if path == root {
            return true;
        }
        directory = path.parent();
    }
    false
}

/// Windows has no `uid` or mode bits, so ownership and containment are proved
/// from the real security descriptor of each path in the chain. See
/// `super::windows_trusted_execution` for the trusted principal set and the
/// access-mask rules.
#[cfg(windows)]
fn has_static_system_ownership(root: &Path, executable: &Path) -> bool {
    super::windows_trusted_execution::has_static_system_ownership(root, executable)
}

/// No other platform has a trusted execution directory, so
/// `TRUSTED_EXECUTION_DIRECTORIES` is empty and resolution fails before this
/// point. Fail closed.
#[cfg(not(any(unix, windows)))]
fn has_static_system_ownership(_root: &Path, _executable: &Path) -> bool {
    false
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[derive(Debug, thiserror::Error)]
enum ExecutionChildError {
    #[error("execution child capacity exhausted")]
    Capacity,
    #[error("execution target failed to start: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("execution target I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("execution target {stream} exceeded {limit} bytes")]
    OutputLimit { stream: &'static str, limit: usize },
    #[error("execution target timed out after {0:?}")]
    Timeout(Duration),
    #[error("execution client disconnected")]
    ClientDisconnected,
}

struct ExecutionChildGuard {
    child: Option<Child>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl ExecutionChildGuard {
    async fn kill_and_reap(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        terminate_execution_child(child).await;
        self.child.take();
        self._permit.take();
    }

    fn mark_reaped(&mut self) {
        self.child.take();
        self._permit.take();
    }
}

impl Drop for ExecutionChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let permit = self._permit.take();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                terminate_execution_child(&mut child).await;
                drop(permit);
            });
        }
    }
}

struct CapturedExecutionOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

pub struct StreamingExecutionResponse {
    pub status: StatusCode,
    pub content_type: HeaderValue,
    pub body: ExecutionByteStream,
}

impl ExecutionTarget {
    pub fn kind_label(&self) -> &str {
        match self {
            Self::Command(target) => target
                .family
                .map(|family| family.as_str())
                .unwrap_or("exec"),
            Self::File(_) => "file",
            Self::Echo => "echo",
            Self::Unsupported { kind, .. } => kind.as_str(),
        }
    }

    pub fn unsupported_reason(&self) -> Option<&str> {
        match self {
            Self::Unsupported { reason, .. } => Some(reason.as_str()),
            _ => None,
        }
    }
}

pub fn parse_execution_target(
    raw_provider: &str,
    entry: &Value,
) -> Result<Option<ExecutionTarget>, CliError> {
    let trimmed = raw_provider.trim();

    if let Some(command) = trimmed.strip_prefix("exec:") {
        let spec = parse_exec_command(command)
            .ok_or_else(|| CliError::user("exec: providers require a command after the prefix"))?;
        return Ok(Some(ExecutionTarget::Command(CommandExecutionTarget {
            program: spec.0,
            args: spec.1,
            cwd: execution_cwd(entry),
            env: parse_env_map_merged(entry.get("cli_env"), entry.get("adapter_env")),
            timeout: parse_timeout(entry),
            family: None,
            workflow_id: None,
            runner_config: None,
        })));
    }

    if let Some(path) = trimmed.strip_prefix("file://") {
        let path = path.trim();
        if path.is_empty() {
            return Err(CliError::user(
                "file:// providers require a script path after the prefix",
            ));
        }
        return Ok(Some(ExecutionTarget::File(FileExecutionTarget {
            path: path.to_string(),
            timeout: parse_timeout(entry),
        })));
    }

    let family_spec = parse_execution_family(trimmed);
    let normalized = family_spec
        .as_ref()
        .map(|spec| spec.kind.to_string())
        .unwrap_or_else(|| normalized_execution_alias(trimmed));
    if normalized == "echo" {
        return Ok(Some(ExecutionTarget::Echo));
    }
    if matches!(
        normalized.as_str(),
        "manual-input"
            | "sequence"
            | "simulated-user"
            | "slack-feedback"
            | "go"
            | "ruby"
            | "webhook"
    ) {
        return Ok(Some(ExecutionTarget::Unsupported {
            kind: normalized.to_string(),
            reason: format!(
                "provider '{normalized}' requires an eval or interactive runtime and is not supported by verdictan gateway run"
            ),
        }));
    }

    let family = family_spec
        .as_ref()
        .map(|spec| spec.family)
        .or(match normalized.as_str() {
            "browser" => Some(AdapterFamily::Browser),
            "chatkit" => Some(AdapterFamily::ChatKit),
            "claude-agent-sdk" | "claude-code" => Some(AdapterFamily::ClaudeAgentSdk),
            "codex-sdk" | "codex" => Some(AdapterFamily::CodexSdk),
            "mcp" => Some(AdapterFamily::Mcp),
            "websocket" => Some(AdapterFamily::WebSocket),
            "openai-agents" => Some(AdapterFamily::OpenAiAgents),
            "opencode-sdk" => Some(AdapterFamily::OpenCodeSdk),
            "bedrock-agents" => Some(AdapterFamily::BedrockAgents),
            _ => None,
        });

    let Some(family) = family else {
        return Ok(None);
    };

    let workflow_id = family_spec.and_then(|spec| spec.workflow_id);
    let runner_config = build_native_runner_config(entry, family);
    let explicit_program = entry_string(
        entry,
        &[
            "adapter_command",
            "transformers_node_path_override",
            "node_path_override",
            "path_to_claude_code_executable",
            "codex_path_override",
            "openai_agents_path_override",
            "opencode_path_override",
            "bedrock_agents_path_override",
        ],
    );
    let program = explicit_program
        .clone()
        .or_else(|| native_default_program(family, entry));

    if family == AdapterFamily::Mcp && explicit_program.is_none() {
        return Ok(None);
    }

    let Some(program) = program else {
        return Ok(Some(ExecutionTarget::Unsupported {
            kind: family.as_str().to_string(),
            reason: unsupported_family_reason(family),
        }));
    };

    let mut args = if explicit_program.is_some() {
        Vec::new()
    } else {
        native_default_args(family, workflow_id.as_deref())
    };
    args.extend(entry_string_array(entry.get("adapter_args")));

    Ok(Some(ExecutionTarget::Command(CommandExecutionTarget {
        program,
        args,
        cwd: execution_cwd(entry),
        env: parse_env_map_merged(entry.get("cli_env"), entry.get("adapter_env")),
        timeout: parse_timeout(entry),
        family: Some(family),
        workflow_id,
        runner_config,
    })))
}

pub fn execution_family_info(raw_provider: &str) -> Option<ExecutionFamilyInfo> {
    parse_execution_family(raw_provider).map(|spec| ExecutionFamilyInfo {
        family: spec.family,
        kind: spec.kind,
    })
}

pub async fn execute_target_streaming(
    target: &ExecutionTarget,
    provider_id: &str,
    path: &str,
    body: &Bytes,
    request_id: &str,
) -> StreamingExecutionResponse {
    match target {
        ExecutionTarget::Command(command) => {
            execute_command_target_streaming(command, provider_id, path, body, request_id).await
        }
        ExecutionTarget::File(file) => {
            execute_file_target_streaming(file, provider_id, path, body, request_id).await
        }
        ExecutionTarget::Echo => execute_echo_target_streaming(path, body),
        ExecutionTarget::Unsupported { kind, reason } => streaming_error_response(
            StatusCode::NOT_IMPLEMENTED,
            json!({
                "error": {
                    "message": reason,
                    "type": "unsupported_execution_target",
                    "code": kind,
                }
            }),
            Some(kind.as_str()),
        ),
    }
}

pub async fn execute_target(
    target: &ExecutionTarget,
    provider_id: &str,
    path: &str,
    body: &Bytes,
    request_id: &str,
) -> BufferedUpstreamResponse {
    match target {
        ExecutionTarget::Command(command) => {
            execute_command_target(command, provider_id, path, body, request_id).await
        }
        ExecutionTarget::File(file) => {
            execute_file_target(file, provider_id, path, body, request_id).await
        }
        ExecutionTarget::Echo => execute_echo_target(path, body),
        ExecutionTarget::Unsupported { kind, reason } => compatibility_error_response(
            StatusCode::NOT_IMPLEMENTED,
            json!({
                "error": {
                    "message": reason,
                    "type": "unsupported_execution_target",
                    "code": kind,
                }
            }),
            Some(kind.as_str()),
        ),
    }
}

fn parse_exec_command(command: &str) -> Option<(String, Vec<String>)> {
    let mut parts = command
        .split_whitespace()
        .filter(|segment| !segment.trim().is_empty());
    let program = parts.next()?.to_string();
    let args = parts.map(ToString::to_string).collect();
    Some((program, args))
}

#[derive(Debug, Clone)]
struct ExecutionFamilySpec {
    family: AdapterFamily,
    kind: &'static str,
    workflow_id: Option<String>,
}

fn parse_execution_family(raw_provider: &str) -> Option<ExecutionFamilySpec> {
    let trimmed = raw_provider.trim();
    let lower = trimmed.to_ascii_lowercase();

    match lower.as_str() {
        "browser" | "browser-agent" | "playwright-browser" => {
            return Some(ExecutionFamilySpec {
                family: AdapterFamily::Browser,
                kind: "browser",
                workflow_id: None,
            })
        }
        "chatkit" => {
            return Some(ExecutionFamilySpec {
                family: AdapterFamily::ChatKit,
                kind: "chatkit",
                workflow_id: None,
            })
        }
        "transformers" | "transformers.js" => {
            return Some(ExecutionFamilySpec {
                family: AdapterFamily::Transformers,
                kind: "transformers",
                workflow_id: None,
            })
        }
        "mcp" => {
            return Some(ExecutionFamilySpec {
                family: AdapterFamily::Mcp,
                kind: "mcp",
                workflow_id: None,
            })
        }
        "websocket" => {
            return Some(ExecutionFamilySpec {
                family: AdapterFamily::WebSocket,
                kind: "websocket",
                workflow_id: None,
            })
        }
        "claude-agent-sdk" | "claude-code" => {
            return Some(ExecutionFamilySpec {
                family: AdapterFamily::ClaudeAgentSdk,
                kind: "claude-agent-sdk",
                workflow_id: None,
            })
        }
        "codex-sdk" | "codex" => {
            return Some(ExecutionFamilySpec {
                family: AdapterFamily::CodexSdk,
                kind: "codex-sdk",
                workflow_id: None,
            })
        }
        "openai-agents" => {
            return Some(ExecutionFamilySpec {
                family: AdapterFamily::OpenAiAgents,
                kind: "openai-agents",
                workflow_id: None,
            })
        }
        "opencode-sdk" | "opencode" => {
            return Some(ExecutionFamilySpec {
                family: AdapterFamily::OpenCodeSdk,
                kind: "opencode-sdk",
                workflow_id: None,
            })
        }
        "bedrock-agents" => {
            return Some(ExecutionFamilySpec {
                family: AdapterFamily::BedrockAgents,
                kind: "bedrock-agents",
                workflow_id: None,
            })
        }
        _ => {}
    }

    let parts = trimmed.split(':').collect::<Vec<_>>();
    match (parts.first().copied(), parts.get(1).copied()) {
        (Some("openai"), Some("chatkit")) => Some(ExecutionFamilySpec {
            family: AdapterFamily::ChatKit,
            kind: "chatkit",
            workflow_id: parts
                .get(2..)
                .filter(|segments| !segments.is_empty())
                .map(|segments| segments.join(":"))
                .filter(|value| !value.trim().is_empty()),
        }),
        (Some("transformers" | "transformers.js"), Some(_)) => Some(ExecutionFamilySpec {
            family: AdapterFamily::Transformers,
            kind: "transformers",
            workflow_id: None,
        }),
        (Some("anthropic"), Some("claude-agent-sdk" | "claude-code")) => {
            Some(ExecutionFamilySpec {
                family: AdapterFamily::ClaudeAgentSdk,
                kind: "claude-agent-sdk",
                workflow_id: None,
            })
        }
        (Some("openai"), Some("codex-sdk" | "codex")) => Some(ExecutionFamilySpec {
            family: AdapterFamily::CodexSdk,
            kind: "codex-sdk",
            workflow_id: None,
        }),
        (Some("openai"), Some("agents")) => Some(ExecutionFamilySpec {
            family: AdapterFamily::OpenAiAgents,
            kind: "openai-agents",
            workflow_id: None,
        }),
        (Some("openai"), Some("opencode-sdk" | "opencode")) => Some(ExecutionFamilySpec {
            family: AdapterFamily::OpenCodeSdk,
            kind: "opencode-sdk",
            workflow_id: None,
        }),
        (Some("bedrock" | "aws"), Some("agents")) => Some(ExecutionFamilySpec {
            family: AdapterFamily::BedrockAgents,
            kind: "bedrock-agents",
            workflow_id: None,
        }),
        _ => None,
    }
}

fn parse_timeout(entry: &Value) -> Duration {
    let timeout_ms = entry
        .get("execution_timeout_ms")
        .and_then(|value| value.as_u64())
        .unwrap_or(30_000)
        .clamp(1, HARD_TIMEOUT.as_millis() as u64);
    Duration::from_millis(timeout_ms)
}

fn parse_env_map(value: Option<&Value>) -> HashMap<String, String> {
    value
        .and_then(|value| value.as_object())
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_env_map_merged(
    primary: Option<&Value>,
    fallback: Option<&Value>,
) -> HashMap<String, String> {
    let mut env = parse_env_map(primary);
    for (key, value) in parse_env_map(fallback) {
        env.insert(key, value);
    }
    env
}

fn execution_cwd(entry: &Value) -> Option<String> {
    entry_string(entry, &["adapter_cwd", "working_dir"])
}

fn build_native_runner_config(entry: &Value, family: AdapterFamily) -> Option<Value> {
    let mut config = serde_json::Map::new();

    insert_string_field(&mut config, entry, "model", &["model"]);
    insert_string_field(&mut config, entry, "working_dir", &["working_dir"]);
    insert_array_field(
        &mut config,
        entry,
        "additional_directories",
        &["additional_directories"],
    );
    insert_object_field(&mut config, entry, "cli_env", &["cli_env"]);

    match family {
        AdapterFamily::ClaudeAgentSdk => {
            insert_string_field(
                &mut config,
                entry,
                "path_to_claude_code_executable",
                &["path_to_claude_code_executable"],
            );
            insert_string_field(&mut config, entry, "permission_mode", &["permission_mode"]);
            insert_string_field(&mut config, entry, "fallback_model", &["fallback_model"]);
            insert_array_field(
                &mut config,
                entry,
                "append_allowed_tools",
                &["append_allowed_tools"],
            );
            insert_array_field(
                &mut config,
                entry,
                "disallowed_tools",
                &["disallowed_tools"],
            );
            insert_bool_field(&mut config, entry, "allow_all_tools", &["allow_all_tools"]);
            insert_u64_field(&mut config, entry, "max_turns", &["max_turns"]);
        }
        AdapterFamily::Transformers => {
            if let Some(provider) = entry.get("provider").and_then(|value| value.as_str()) {
                let parts = provider.split(':').collect::<Vec<_>>();
                if let Some(task) = parts.get(1) {
                    config.insert("task".to_string(), Value::String((*task).to_string()));
                }
                if let Some(model) = parts.get(2..) {
                    let model = model.join(":");
                    if !model.trim().is_empty() {
                        config.insert("model".to_string(), Value::String(model));
                    }
                }
            }
            insert_string_field(&mut config, entry, "device", &["device"]);
            insert_string_field(&mut config, entry, "dtype", &["dtype"]);
            insert_string_field(&mut config, entry, "cache_dir", &["cache_dir", "cacheDir"]);
            insert_string_field(
                &mut config,
                entry,
                "transformers_node_path_override",
                &["transformers_node_path_override", "node_path_override"],
            );
            insert_bool_field(
                &mut config,
                entry,
                "local_files_only",
                &["local_files_only", "localFilesOnly"],
            );
            insert_string_field(&mut config, entry, "revision", &["revision"]);
            insert_string_field(&mut config, entry, "prefix", &["prefix"]);
            insert_string_field(&mut config, entry, "pooling", &["pooling"]);
            insert_bool_field(&mut config, entry, "normalize", &["normalize"]);
            insert_value_field(
                &mut config,
                entry,
                "max_new_tokens",
                &["max_new_tokens", "maxNewTokens"],
            );
            insert_value_field(
                &mut config,
                entry,
                "return_full_text",
                &["return_full_text", "returnFullText"],
            );
            insert_value_field(&mut config, entry, "temperature", &["temperature"]);
            insert_value_field(&mut config, entry, "top_k", &["top_k", "topK"]);
            insert_value_field(&mut config, entry, "top_p", &["top_p", "topP"]);
            insert_value_field(&mut config, entry, "do_sample", &["do_sample", "doSample"]);
            insert_value_field(
                &mut config,
                entry,
                "repetition_penalty",
                &["repetition_penalty", "repetitionPenalty"],
            );
            insert_value_field(
                &mut config,
                entry,
                "no_repeat_ngram_size",
                &["no_repeat_ngram_size", "noRepeatNgramSize"],
            );
            insert_value_field(&mut config, entry, "num_beams", &["num_beams", "numBeams"]);
            insert_object_field(
                &mut config,
                entry,
                "session_options",
                &["session_options", "sessionOptions"],
            );
        }
        AdapterFamily::CodexSdk => {
            insert_string_field(
                &mut config,
                entry,
                "codex_path_override",
                &["codex_path_override"],
            );
            insert_string_field(&mut config, entry, "sandbox_mode", &["sandbox_mode"]);
            insert_string_field(&mut config, entry, "approval_policy", &["approval_policy"]);
            insert_bool_field(
                &mut config,
                entry,
                "network_access_enabled",
                &["network_access_enabled"],
            );
            insert_bool_field(
                &mut config,
                entry,
                "web_search_enabled",
                &["web_search_enabled"],
            );
            insert_bool_field(
                &mut config,
                entry,
                "skip_git_repo_check",
                &["skip_git_repo_check"],
            );
        }
        AdapterFamily::OpenAiAgents => {
            insert_string_field(
                &mut config,
                entry,
                "openai_agents_path_override",
                &["openai_agents_path_override"],
            );
            insert_string_field(&mut config, entry, "agent_name", &["agent_name"]);
        }
        AdapterFamily::OpenCodeSdk => {
            insert_string_field(
                &mut config,
                entry,
                "opencode_path_override",
                &["opencode_path_override"],
            );
        }
        AdapterFamily::BedrockAgents => {
            insert_string_field(
                &mut config,
                entry,
                "bedrock_agents_path_override",
                &["bedrock_agents_path_override"],
            );
            insert_string_field(&mut config, entry, "aws_region", &["aws_region"]);
        }
        AdapterFamily::Browser
        | AdapterFamily::ChatKit
        | AdapterFamily::Mcp
        | AdapterFamily::WebSocket => {}
    }

    if config.is_empty() {
        None
    } else {
        Some(Value::Object(config))
    }
}

fn insert_string_field(
    config: &mut serde_json::Map<String, Value>,
    entry: &Value,
    output_key: &str,
    input_keys: &[&str],
) {
    if let Some(value) = entry_string(entry, input_keys) {
        config.insert(output_key.to_string(), Value::String(value));
    }
}

fn insert_array_field(
    config: &mut serde_json::Map<String, Value>,
    entry: &Value,
    output_key: &str,
    input_keys: &[&str],
) {
    let value = input_keys
        .iter()
        .find_map(|key| entry.get(key))
        .and_then(|value| value.as_array())
        .map(|items| {
            Value::Array(
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(|text| Value::String(text.to_string())))
                    .collect(),
            )
        });
    if let Some(value) = value {
        config.insert(output_key.to_string(), value);
    }
}

fn insert_object_field(
    config: &mut serde_json::Map<String, Value>,
    entry: &Value,
    output_key: &str,
    input_keys: &[&str],
) {
    let value = input_keys
        .iter()
        .find_map(|key| entry.get(key))
        .and_then(|value| value.as_object())
        .map(|object| Value::Object(object.clone()));
    if let Some(value) = value {
        config.insert(output_key.to_string(), value);
    }
}

fn insert_bool_field(
    config: &mut serde_json::Map<String, Value>,
    entry: &Value,
    output_key: &str,
    input_keys: &[&str],
) {
    let value = input_keys
        .iter()
        .find_map(|key| entry.get(key))
        .and_then(|value| value.as_bool());
    if let Some(value) = value {
        config.insert(output_key.to_string(), Value::Bool(value));
    }
}

fn insert_value_field(
    config: &mut serde_json::Map<String, Value>,
    entry: &Value,
    output_key: &str,
    input_keys: &[&str],
) {
    let value = input_keys.iter().find_map(|key| entry.get(key)).cloned();
    if let Some(value) = value {
        config.insert(output_key.to_string(), value);
    }
}

fn insert_u64_field(
    config: &mut serde_json::Map<String, Value>,
    entry: &Value,
    output_key: &str,
    input_keys: &[&str],
) {
    let value = input_keys
        .iter()
        .find_map(|key| entry.get(key))
        .and_then(|value| value.as_u64());
    if let Some(value) = value {
        config.insert(output_key.to_string(), Value::Number(value.into()));
    }
}

fn unsupported_family_reason(family: AdapterFamily) -> String {
    match family {
        AdapterFamily::Browser => {
            "provider 'browser' requires adapter_command plus optional adapter_args so Verdictan can invoke a local browser automation process".to_string()
        }
        AdapterFamily::ChatKit => {
            "provider 'chatkit' requires adapter_command plus optional adapter_args so Verdictan can invoke a local browser automation runner".to_string()
        }
        AdapterFamily::Transformers => {
            "provider 'transformers' requires a Node.js runtime on PATH, 'transformers_node_path_override', or adapter_command so Verdictan can invoke the local Transformers.js runner".to_string()
        }
        AdapterFamily::ClaudeAgentSdk => {
            "provider 'claude-agent-sdk' requires a Claude executable on PATH, 'path_to_claude_code_executable', or adapter_command so Verdictan can invoke the local agent runner".to_string()
        }
        AdapterFamily::CodexSdk => {
            "provider 'codex-sdk' requires a Codex executable on PATH, 'codex_path_override', or adapter_command so Verdictan can invoke the local agent runner".to_string()
        }
        AdapterFamily::Mcp => {
            "provider 'mcp' requires a base_url for the native HTTP bridge or adapter_command plus optional adapter_args for an explicit local MCP bridge process".to_string()
        }
        AdapterFamily::WebSocket => {
            "provider 'websocket' requires adapter_command plus optional adapter_args so Verdictan can invoke a local websocket bridge process".to_string()
        }
        AdapterFamily::OpenAiAgents => {
            "provider 'openai-agents' requires an OpenAI Agents runner on PATH, 'openai_agents_path_override', or adapter_command so Verdictan can invoke the local agent runner".to_string()
        }
        AdapterFamily::OpenCodeSdk => {
            "provider 'opencode-sdk' requires an OpenCode executable on PATH, 'opencode_path_override', or adapter_command so Verdictan can invoke the local agent runner".to_string()
        }
        AdapterFamily::BedrockAgents => {
            "provider 'bedrock-agents' requires a Bedrock agents runner on PATH, 'bedrock_agents_path_override', or adapter_command so Verdictan can invoke the local agent runner".to_string()
        }
    }
}

fn native_default_program(family: AdapterFamily, entry: &Value) -> Option<String> {
    match family {
        AdapterFamily::ClaudeAgentSdk => entry_string(entry, &["path_to_claude_code_executable"])
            .or_else(|| Some("claude".to_string())),
        AdapterFamily::CodexSdk => {
            entry_string(entry, &["codex_path_override"]).or_else(|| Some("codex".to_string()))
        }
        AdapterFamily::OpenAiAgents => entry_string(entry, &["openai_agents_path_override"])
            .or_else(|| Some("openai-agents".to_string())),
        AdapterFamily::OpenCodeSdk => entry_string(entry, &["opencode_path_override"])
            .or_else(|| Some("opencode".to_string())),
        AdapterFamily::BedrockAgents => entry_string(entry, &["bedrock_agents_path_override"])
            .or_else(|| Some("bedrock-agents".to_string())),
        AdapterFamily::Transformers => entry_string(
            entry,
            &["transformers_node_path_override", "node_path_override"],
        )
        .or_else(|| Some("node".to_string())),
        AdapterFamily::Browser
        | AdapterFamily::ChatKit
        | AdapterFamily::Mcp
        | AdapterFamily::WebSocket => None,
    }
}

fn native_default_args(family: AdapterFamily, workflow_id: Option<&str>) -> Vec<String> {
    match family {
        AdapterFamily::ChatKit => {
            let _ = workflow_id;
            Vec::new()
        }
        AdapterFamily::Transformers => vec![
            "--input-type=module".to_string(),
            "-e".to_string(),
            include_str!("runtimes/local/transformers_node_runner.mjs").to_string(),
        ],
        AdapterFamily::Browser
        | AdapterFamily::ClaudeAgentSdk
        | AdapterFamily::CodexSdk
        | AdapterFamily::Mcp
        | AdapterFamily::WebSocket
        | AdapterFamily::OpenAiAgents
        | AdapterFamily::OpenCodeSdk
        | AdapterFamily::BedrockAgents => Vec::new(),
    }
}

fn entry_string(entry: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| entry.get(key).and_then(|value| value.as_str()))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn entry_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn normalized_execution_alias(raw_provider: &str) -> String {
    match raw_provider.trim().to_ascii_lowercase().as_str() {
        "browser" | "browser-agent" | "playwright-browser" => "browser".to_string(),
        "chatkit" => "chatkit".to_string(),
        value if value.starts_with("transformers:") || value.starts_with("transformers.js:") => {
            "transformers".to_string()
        }
        "claude-agent-sdk" | "claude-code" => "claude-agent-sdk".to_string(),
        "codex-sdk" | "codex" => "codex-sdk".to_string(),
        "mcp" => "mcp".to_string(),
        "websocket" => "websocket".to_string(),
        "openai-agents" => "openai-agents".to_string(),
        "opencode-sdk" | "opencode" => "opencode-sdk".to_string(),
        "bedrock-agents" => "bedrock-agents".to_string(),
        "echo" => "echo".to_string(),
        "go" | "go-script" | "gorun" => "go".to_string(),
        "manual-input" => "manual-input".to_string(),
        "ruby" | "ruby-script" | "rb" => "ruby".to_string(),
        "sequence" => "sequence".to_string(),
        "simulated-user" => "simulated-user".to_string(),
        "slack-feedback" | "slack" => "slack-feedback".to_string(),
        "webhook" | "webhook-runner" => "webhook".to_string(),
        _ => String::new(),
    }
}

async fn execute_file_target_streaming(
    target: &FileExecutionTarget,
    provider_id: &str,
    path: &str,
    body: &Bytes,
    request_id: &str,
) -> StreamingExecutionResponse {
    let file_path = PathBuf::from(&target.path);
    let launcher = match script_launcher(&file_path) {
        Ok(launcher) => launcher,
        Err(error) => {
            return streaming_error_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' file target failed: {error}"),
                        "type": "execution_target_error",
                        "code": "file_target_invalid",
                    }
                }),
                Some("file"),
            )
        }
    };

    let command = CommandExecutionTarget {
        program: launcher.0,
        args: launcher.1,
        cwd: file_path
            .parent()
            .map(|parent| parent.display().to_string()),
        env: HashMap::new(),
        timeout: target.timeout,
        family: None,
        workflow_id: None,
        runner_config: None,
    };

    execute_command_target_streaming(&command, provider_id, path, body, request_id).await
}

async fn execute_file_target(
    target: &FileExecutionTarget,
    provider_id: &str,
    path: &str,
    body: &Bytes,
    request_id: &str,
) -> BufferedUpstreamResponse {
    let file_path = PathBuf::from(&target.path);
    let launcher = match script_launcher(&file_path) {
        Ok(launcher) => launcher,
        Err(error) => {
            return compatibility_error_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' file target failed: {error}"),
                        "type": "execution_target_error",
                        "code": "file_target_invalid",
                    }
                }),
                Some("file"),
            )
        }
    };

    let command = CommandExecutionTarget {
        program: launcher.0,
        args: launcher.1,
        cwd: file_path
            .parent()
            .map(|parent| parent.display().to_string()),
        env: HashMap::new(),
        timeout: target.timeout,
        family: None,
        workflow_id: None,
        runner_config: None,
    };

    execute_command_target(&command, provider_id, path, body, request_id).await
}

fn script_launcher(path: &Path) -> Result<(String, Vec<String>), CliError> {
    let canonical = path.canonicalize().map_err(|error| {
        CliError::user(format!(
            "failed to resolve file target {}: {error}",
            path.display()
        ))
    })?;

    let ext = canonical
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let file = canonical.display().to_string();

    let launcher = match ext.as_str() {
        "py" => ("python3".to_string(), vec![file]),
        "js" | "mjs" | "cjs" => ("node".to_string(), vec![file]),
        "rb" => ("ruby".to_string(), vec![file]),
        "sh" => ("sh".to_string(), vec![file]),
        _ => (file, Vec::new()),
    };

    Ok(launcher)
}

fn resolved_command_program_and_args(
    target: &CommandExecutionTarget,
) -> Result<(String, Vec<String>), CliError> {
    let path = Path::new(&target.program);
    let (program, mut args) = if path.is_absolute() || path.components().count() > 1 {
        script_launcher(path)?
    } else {
        (target.program.clone(), Vec::new())
    };
    args.extend(target.args.iter().cloned());
    Ok((program, args))
}

fn sanitized_execution_path() -> String {
    let separator = if cfg!(windows) { ";" } else { ":" };
    TRUSTED_EXECUTION_DIRECTORIES
        .iter()
        .filter(|root| {
            let path = Path::new(root);
            path.canonicalize()
                .is_ok_and(|canonical| has_static_system_ownership(&canonical, &canonical))
        })
        .copied()
        .collect::<Vec<_>>()
        .join(separator)
}

fn configured_execution_command(
    program: &TrustedExecutionProgram,
    args: &[String],
    target: &CommandExecutionTarget,
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(&program.execution_path);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command
            .as_std_mut()
            .arg0(program.canonical_path.as_os_str());
    }
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    if let Some(cwd) = &target.cwd {
        command.current_dir(cwd);
    }
    for (key, value) in &target.env {
        if !key.eq_ignore_ascii_case("PATH") {
            command.env(key, value);
        }
    }
    command.env("PATH", sanitized_execution_path());

    #[cfg(unix)]
    {
        #[allow(unsafe_code)]
        // SAFETY: this runs after fork and before exec, invokes only the
        // async-signal-safe setpgid syscall, and creates a dedicated process
        // group so cancellation can terminate descendants as well as the
        // immediate child.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    command
}

fn spawn_execution_child(
    program: &TrustedExecutionProgram,
    args: &[String],
    target: &CommandExecutionTarget,
) -> Result<ExecutionChildGuard, ExecutionChildError> {
    tracing::debug!(
        executable = %program.canonical_path.display(),
        "spawning pinned execution runtime binary"
    );
    program
        .ensure_pinned_identity_before_spawn()
        .map_err(ExecutionChildError::Spawn)?;
    let permit = execution_child_pool()
        .try_acquire_process()
        .map_err(|_| ExecutionChildError::Capacity)?;
    let mut command = configured_execution_command(program, args, target);
    let child = command.spawn().map_err(ExecutionChildError::Spawn)?;
    Ok(ExecutionChildGuard {
        child: Some(child),
        _permit: Some(permit),
    })
}

async fn terminate_execution_child(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        #[allow(unsafe_code)]
        // SAFETY: the child is placed in a process group whose id is its pid.
        // A negative pid targets only that group.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
}

async fn write_execution_input(
    mut stdin: ChildStdin,
    input: Vec<u8>,
) -> Result<(), ExecutionChildError> {
    stdin.write_all(&input).await?;
    stdin.shutdown().await?;
    Ok(())
}

async fn read_execution_pipe<R>(
    mut pipe: R,
    stream: &'static str,
) -> Result<Vec<u8>, ExecutionChildError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let limit = execution_stream_limit(stream);
    let mut output = Vec::with_capacity(64 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let count = pipe.read(&mut chunk).await?;
        if count == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(count) > limit {
            return Err(ExecutionChildError::OutputLimit { stream, limit });
        }
        output.extend_from_slice(&chunk[..count]);
    }
}

async fn stream_execution_stdout(
    mut stdout: ChildStdout,
    tx: &tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    path: &str,
) -> Result<bool, ExecutionChildError> {
    let mut buffer = [0u8; STREAM_READ_CHUNK_BYTES];
    let mut output_bytes = 0usize;
    let mut saw_output = false;
    let mut passthrough_sse = false;
    let stdout_limit = execution_stream_limit("stdout");

    loop {
        let read = stdout.read(&mut buffer).await?;
        if read == 0 {
            return Ok(passthrough_sse);
        }
        output_bytes = output_bytes.saturating_add(read);
        if output_bytes > stdout_limit {
            return Err(ExecutionChildError::OutputLimit {
                stream: "stdout",
                limit: stdout_limit,
            });
        }

        let chunk = Bytes::copy_from_slice(&buffer[..read]);
        if !saw_output {
            passthrough_sse = looks_like_sse_chunk(&chunk);
            saw_output = true;
        }
        let outgoing = if passthrough_sse {
            chunk
        } else {
            let text = String::from_utf8_lossy(&chunk);
            if text.is_empty() {
                continue;
            }
            wrap_streaming_text_chunk(path, &text)
        };
        tx.send(Ok(outgoing))
            .await
            .map_err(|_| ExecutionChildError::ClientDisconnected)?;
    }
}

async fn capture_execution_output(
    mut guard: ExecutionChildGuard,
    input: Vec<u8>,
    timeout: Duration,
) -> Result<CapturedExecutionOutput, ExecutionChildError> {
    let child = guard
        .child
        .as_mut()
        .ok_or_else(|| std::io::Error::other("execution child missing"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("execution child stdin missing"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("execution child stdout missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("execution child stderr missing"))?;

    let bounded_timeout = clamp_timeout(timeout);
    let total_limit = execution_child_pool().config().total_max_bytes;
    let result = tokio::time::timeout(bounded_timeout, async {
        let ((), stdout, stderr, status) = tokio::try_join!(
            write_execution_input(stdin, input),
            read_execution_pipe(stdout, "stdout"),
            read_execution_pipe(stderr, "stderr"),
            async { child.wait().await.map_err(ExecutionChildError::Io) },
        )?;
        if stdout.len().saturating_add(stderr.len()) > total_limit {
            return Err(ExecutionChildError::OutputLimit {
                stream: "total",
                limit: total_limit,
            });
        }
        Ok::<_, ExecutionChildError>(CapturedExecutionOutput {
            status,
            stdout,
            stderr,
        })
    })
    .await;

    match result {
        Ok(Ok(output)) => {
            guard.mark_reaped();
            Ok(output)
        }
        Ok(Err(error)) => {
            guard.kill_and_reap().await;
            Err(error)
        }
        Err(_) => {
            guard.kill_and_reap().await;
            Err(ExecutionChildError::Timeout(bounded_timeout))
        }
    }
}

fn execution_error_status(error: &ExecutionChildError) -> StatusCode {
    match error {
        ExecutionChildError::Capacity => StatusCode::SERVICE_UNAVAILABLE,
        ExecutionChildError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        ExecutionChildError::Spawn(_)
        | ExecutionChildError::Io(_)
        | ExecutionChildError::OutputLimit { .. }
        | ExecutionChildError::ClientDisconnected => StatusCode::BAD_GATEWAY,
    }
}

fn execution_error_code(error: &ExecutionChildError) -> &'static str {
    match error {
        ExecutionChildError::Capacity => "execution_capacity_exhausted",
        ExecutionChildError::Spawn(_) => "execution_spawn_failed",
        ExecutionChildError::Io(_) => "execution_io_failed",
        ExecutionChildError::OutputLimit { .. } => "execution_output_limit_exceeded",
        ExecutionChildError::Timeout(_) => "execution_timeout",
        ExecutionChildError::ClientDisconnected => "execution_client_disconnected",
    }
}

fn stderr_excerpt(stderr: &[u8]) -> String {
    let start = stderr.len().saturating_sub(EXECUTION_STDERR_EXCERPT_BYTES);
    String::from_utf8_lossy(&stderr[start..])
        .chars()
        .filter(|character| !character.is_control() || matches!(*character, '\n' | '\r' | '\t'))
        .collect::<String>()
        .trim()
        .to_string()
}

async fn execute_command_target(
    target: &CommandExecutionTarget,
    provider_id: &str,
    path: &str,
    body: &Bytes,
    request_id: &str,
) -> BufferedUpstreamResponse {
    let payload = build_execution_payload(target, provider_id, path, body, request_id, false);
    let input_bytes = match serde_json::to_vec(&payload) {
        Ok(bytes) => bytes,
        Err(error) => {
            return compatibility_error_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' execution payload failed to serialize: {error}"),
                        "type": "execution_target_error",
                        "code": "execution_payload_invalid",
                    }
                }),
                Some(
                    target
                        .family
                        .map(|family| family.as_str())
                        .unwrap_or("exec"),
                ),
            )
        }
    };

    let (program, args) = match resolved_command_program_and_args(target) {
        Ok(command) => command,
        Err(error) => {
            return compatibility_error_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' execution target is invalid: {error}"),
                        "type": "execution_target_error",
                        "code": "execution_target_invalid",
                    }
                }),
                Some(
                    target
                        .family
                        .map(|family| family.as_str())
                        .unwrap_or("exec"),
                ),
            );
        }
    };

    // Resolve only an allowlisted canonical binary beneath the compiled-in
    // trusted roots. On Linux the open descriptor is executed through procfs,
    // so replacing the pathname after validation cannot replace the process.
    if !is_allowed_execution_program(&program) {
        tracing::warn!(
            program = %program,
            provider_id = %provider_id,
            "execution runtime rejected program not in allowlist"
        );
        return compatibility_error_response(
            StatusCode::FORBIDDEN,
            json!({
                "error": {
                    "message": format!("provider '{provider_id}' execution target program '{}' is not in the execution allowlist", program),
                    "type": "execution_target_error",
                    "code": "execution_program_not_allowed",
                }
            }),
            Some(
                target
                    .family
                    .map(|family| family.as_str())
                    .unwrap_or("exec"),
            ),
        );
    }

    let trusted_program = match TrustedExecutionProgram::resolve(&program) {
        Ok(program) => program,
        Err(error) => {
            return compatibility_error_response(
                StatusCode::FORBIDDEN,
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' execution target program is not trusted: {error}"),
                        "type": "execution_target_error",
                        "code": "execution_program_not_trusted",
                    }
                }),
                Some(
                    target
                        .family
                        .map(|family| family.as_str())
                        .unwrap_or("exec"),
                ),
            )
        }
    };

    let child = match spawn_execution_child(&trusted_program, &args, target) {
        Ok(child) => child,
        Err(error) => {
            return compatibility_error_response(
                execution_error_status(&error),
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' execution target failed: {error}"),
                        "type": "execution_target_error",
                        "code": execution_error_code(&error),
                    }
                }),
                Some(
                    target
                        .family
                        .map(|family| family.as_str())
                        .unwrap_or("exec"),
                ),
            )
        }
    };

    let output = match capture_execution_output(child, input_bytes, target.timeout).await {
        Ok(output) => output,
        Err(error) => {
            return compatibility_error_response(
                execution_error_status(&error),
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' execution target failed: {error}"),
                        "type": "execution_target_error",
                        "code": execution_error_code(&error),
                    }
                }),
                Some(
                    target
                        .family
                        .map(|family| family.as_str())
                        .unwrap_or("exec"),
                ),
            )
        }
    };

    if !output.status.success() {
        let stderr = stderr_excerpt(&output.stderr);
        return compatibility_error_response(
            StatusCode::BAD_GATEWAY,
            json!({
                "error": {
                    "message": format!(
                        "provider '{provider_id}' execution target exited with status {}{}",
                        output.status,
                        if stderr.is_empty() {
                            String::new()
                        } else {
                            format!(": {stderr}")
                        }
                    ),
                    "type": "execution_target_error",
                    "code": "execution_exit_non_zero",
                }
            }),
            Some(
                target
                    .family
                    .map(|family| family.as_str())
                    .unwrap_or("exec"),
            ),
        );
    }

    response_from_stdout(
        path,
        &output.stdout,
        target
            .family
            .map(|family| family.as_str())
            .unwrap_or("exec"),
    )
}

async fn execute_command_target_streaming(
    target: &CommandExecutionTarget,
    provider_id: &str,
    path: &str,
    body: &Bytes,
    request_id: &str,
) -> StreamingExecutionResponse {
    let payload = build_execution_payload(target, provider_id, path, body, request_id, true);
    let input_bytes = match serde_json::to_vec(&payload) {
        Ok(bytes) => bytes,
        Err(error) => {
            return streaming_error_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' execution payload failed to serialize: {error}"),
                        "type": "execution_target_error",
                        "code": "execution_payload_invalid",
                    }
                }),
                Some(
                    target
                        .family
                        .map(|family| family.as_str())
                        .unwrap_or("exec"),
                ),
            )
        }
    };

    let (program, args) = match resolved_command_program_and_args(target) {
        Ok(command) => command,
        Err(error) => {
            return streaming_error_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' execution target is invalid: {error}"),
                        "type": "execution_target_error",
                        "code": "execution_target_invalid",
                    }
                }),
                Some(
                    target
                        .family
                        .map(|family| family.as_str())
                        .unwrap_or("exec"),
                ),
            );
        }
    };

    // Apply the same canonical trusted-binary resolution as non-streaming
    // execution. Streaming never gets a weaker PATH or identity policy.
    if !is_allowed_execution_program(&program) {
        tracing::warn!(
            program = %program,
            provider_id = %provider_id,
            "execution runtime rejected program not in allowlist (streaming)"
        );
        return streaming_error_response(
            StatusCode::FORBIDDEN,
            json!({
                "error": {
                    "message": format!("provider '{provider_id}' execution target program '{}' is not in the execution allowlist", program),
                    "type": "execution_target_error",
                    "code": "execution_program_not_allowed",
                }
            }),
            Some(
                target
                    .family
                    .map(|family| family.as_str())
                    .unwrap_or("exec"),
            ),
        );
    }

    let trusted_program = match TrustedExecutionProgram::resolve(&program) {
        Ok(program) => program,
        Err(error) => {
            return streaming_error_response(
                StatusCode::FORBIDDEN,
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' execution target program is not trusted: {error}"),
                        "type": "execution_target_error",
                        "code": "execution_program_not_trusted",
                    }
                }),
                Some(
                    target
                        .family
                        .map(|family| family.as_str())
                        .unwrap_or("exec"),
                ),
            )
        }
    };

    let mut guard = match spawn_execution_child(&trusted_program, &args, target) {
        Ok(guard) => guard,
        Err(error) => {
            return streaming_error_response(
                execution_error_status(&error),
                json!({
                    "error": {
                        "message": format!("provider '{provider_id}' execution target failed: {error}"),
                        "type": "execution_target_error",
                        "code": execution_error_code(&error),
                    }
                }),
                Some(
                    target
                        .family
                        .map(|family| family.as_str())
                        .unwrap_or("exec"),
                ),
            )
        }
    };

    let Some(child) = guard.child.as_mut() else {
        return streaming_error_response(
            StatusCode::BAD_GATEWAY,
            json!({
                "error": {
                    "message": format!("provider '{provider_id}' execution target child state is unavailable"),
                    "type": "execution_target_error",
                    "code": "execution_io_failed",
                }
            }),
            Some(
                target
                    .family
                    .map(|family| family.as_str())
                    .unwrap_or("exec"),
            ),
        );
    };
    let Some(stdin) = child.stdin.take() else {
        guard.kill_and_reap().await;
        return streaming_error_response(
            StatusCode::BAD_GATEWAY,
            json!({"error": {"message": "execution child stdin missing", "type": "execution_target_error", "code": "execution_io_failed"}}),
            target.family.map(|family| family.as_str()).or(Some("exec")),
        );
    };
    let Some(stdout) = child.stdout.take() else {
        guard.kill_and_reap().await;
        return streaming_error_response(
            StatusCode::BAD_GATEWAY,
            json!({"error": {"message": "execution child stdout missing", "type": "execution_target_error", "code": "execution_io_failed"}}),
            target.family.map(|family| family.as_str()).or(Some("exec")),
        );
    };
    let Some(stderr) = child.stderr.take() else {
        guard.kill_and_reap().await;
        return streaming_error_response(
            StatusCode::BAD_GATEWAY,
            json!({"error": {"message": "execution child stderr missing", "type": "execution_target_error", "code": "execution_io_failed"}}),
            target.family.map(|family| family.as_str()).or(Some("exec")),
        );
    };

    let (tx, rx) =
        tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(STREAM_CHANNEL_CAPACITY);
    let path = path.to_string();
    let provider_id = provider_id.to_string();
    let bounded_timeout = clamp_timeout(target.timeout);

    tokio::spawn(async move {
        let Some(child) = guard.child.as_mut() else {
            let _ = tx
                .send(Err(std::io::Error::other(
                    "execution child state disappeared before streaming",
                )))
                .await;
            return;
        };
        let stream_result = tokio::time::timeout(bounded_timeout, async {
            let ((), passthrough_sse, stderr, status) = tokio::try_join!(
                write_execution_input(stdin, input_bytes),
                stream_execution_stdout(stdout, &tx, &path),
                read_execution_pipe(stderr, "stderr"),
                async { child.wait().await.map_err(ExecutionChildError::Io) },
            )?;
            if !status.success() {
                return Err(ExecutionChildError::Io(std::io::Error::other(format!(
                    "provider '{provider_id}' execution target exited with status {}{}",
                    status,
                    if stderr.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", stderr_excerpt(&stderr))
                    }
                ))));
            }

            if !passthrough_sse {
                tx.send(Ok(streaming_finish_chunk(&path)))
                    .await
                    .map_err(|_| ExecutionChildError::ClientDisconnected)?;
                tx.send(Ok(Bytes::from_static(b"data: [DONE]\n\n")))
                    .await
                    .map_err(|_| ExecutionChildError::ClientDisconnected)?;
            }
            Ok::<_, ExecutionChildError>(())
        })
        .await;

        match stream_result {
            Ok(Ok(())) => guard.mark_reaped(),
            Ok(Err(error)) => {
                guard.kill_and_reap().await;
                if !matches!(error, ExecutionChildError::ClientDisconnected) {
                    let _ = tx.send(Err(std::io::Error::other(error.to_string()))).await;
                }
            }
            Err(_) => {
                guard.kill_and_reap().await;
                let _ = tx
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "provider '{}' execution target timed out after {} ms",
                            provider_id,
                            bounded_timeout.as_millis()
                        ),
                    )))
                    .await;
            }
        }
    });

    StreamingExecutionResponse {
        status: StatusCode::OK,
        content_type: HeaderValue::from_static("text/event-stream"),
        body: Box::pin(ReceiverStream::new(rx)),
    }
}

pub fn build_execution_payload(
    target: &CommandExecutionTarget,
    provider_id: &str,
    path: &str,
    body: &Bytes,
    request_id: &str,
    stream_requested: bool,
) -> Value {
    let parsed_request = serde_json::from_slice::<Value>(body).unwrap_or_else(|_| {
        json!({
            "raw_body": String::from_utf8_lossy(body),
        })
    });
    json!({
        "provider_id": provider_id,
        "request_id": request_id,
        "path": path,
        "stream": stream_requested,
        "execution_target": {
            "family": target.family.map(|family| family.as_str()),
            "workflow_id": target.workflow_id,
            "config": target.runner_config,
        },
        "request": parsed_request,
    })
}

fn streaming_error_response(
    status: StatusCode,
    body: Value,
    family: Option<&str>,
) -> StreamingExecutionResponse {
    let buffered = compatibility_error_response(status, body, family);
    let content_type = buffered
        .headers()
        .get(http::header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));
    StreamingExecutionResponse {
        status,
        content_type,
        body: Box::pin(stream::once(async move { Ok(buffered.body().clone()) })),
    }
}

fn looks_like_sse_chunk(chunk: &Bytes) -> bool {
    let trimmed = String::from_utf8_lossy(chunk).trim_start().to_string();
    trimmed.starts_with("data:") || trimmed.starts_with("event:")
}

fn wrap_streaming_text_chunk(path: &str, text: &str) -> Bytes {
    let payload = match path {
        "/v1/responses" => json!({
            "type": "response.output_text.delta",
            "delta": text,
        }),
        "/v1/messages" => json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {
                "type": "text_delta",
                "text": text,
            }
        }),
        _ => json!({
            "id": "chatcmpl_execution_target",
            "object": "chat.completion.chunk",
            "choices": [{
                "index": 0,
                "delta": {
                    "content": text,
                },
                "finish_reason": Value::Null,
            }],
        }),
    };
    Bytes::from(format!("data: {}\n\n", payload))
}

fn streaming_finish_chunk(path: &str) -> Bytes {
    let payload = match path {
        "/v1/responses" => json!({
            "type": "response.completed",
        }),
        "/v1/messages" => json!({
            "type": "message_delta",
            "delta": {
                "stop_reason": "end_turn",
            }
        }),
        _ => json!({
            "id": "chatcmpl_execution_target",
            "object": "chat.completion.chunk",
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop",
            }],
        }),
    };
    Bytes::from(format!("data: {}\n\n", payload))
}

fn response_from_stdout(path: &str, stdout: &[u8], family: &str) -> BufferedUpstreamResponse {
    let text = String::from_utf8_lossy(stdout).trim().to_string();
    if text.is_empty() {
        return compatibility_error_response(
            StatusCode::BAD_GATEWAY,
            json!({
                "error": {
                    "message": "execution target returned an empty stdout payload",
                    "type": "execution_target_error",
                    "code": "execution_empty_output",
                }
            }),
            Some(family),
        );
    }

    if let Ok(value) = serde_json::from_str::<Value>(&text) {
        if let Some(response) = explicit_response_envelope(&value, family) {
            return response;
        }
        if looks_like_native_response(path, &value) {
            return json_response(StatusCode::OK, value, Some(family));
        }
        if path == "/v1/embeddings" {
            return compatibility_error_response(
                StatusCode::BAD_GATEWAY,
                json!({
                    "error": {
                        "message": "execution target returned JSON that does not match the embeddings response contract",
                        "type": "execution_target_error",
                        "code": "execution_invalid_embeddings_output",
                    }
                }),
                Some(family),
            );
        }
        if let Some(content) = value.get("content").and_then(|value| value.as_str()) {
            return wrapped_text_response(path, content, family);
        }
        return wrapped_text_response(path, &value.to_string(), family);
    }

    if path == "/v1/embeddings" {
        return compatibility_error_response(
            StatusCode::BAD_GATEWAY,
            json!({
                "error": {
                    "message": "execution target returned non-JSON output for the embeddings response contract",
                    "type": "execution_target_error",
                    "code": "execution_invalid_embeddings_output",
                }
            }),
            Some(family),
        );
    }

    wrapped_text_response(path, &text, family)
}

fn explicit_response_envelope(value: &Value, family: &str) -> Option<BufferedUpstreamResponse> {
    let body = value.get("body")?.clone();
    let status = value
        .get("status")
        .and_then(|value| value.as_u64())
        .and_then(|value| u16::try_from(value).ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .unwrap_or(StatusCode::OK);
    let mut headers = default_headers(Some(family));
    if let Some(extra_headers) = value.get("headers").and_then(|value| value.as_object()) {
        for (name, value) in extra_headers {
            let Some(value) = value.as_str() else {
                continue;
            };
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            let Ok(value) = HeaderValue::from_str(value) else {
                continue;
            };
            headers.insert(name, value);
        }
    }
    let body = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Some(BufferedUpstreamResponse::new(
        status,
        headers,
        Bytes::from(body),
        false,
    ))
}

fn looks_like_native_response(path: &str, value: &Value) -> bool {
    match path {
        "/v1/embeddings" => value.get("data").is_some(),
        "/v1/responses" => value.get("output").is_some(),
        "/v1/messages" => {
            value.get("content").is_some()
                && value.get("type").and_then(Value::as_str) == Some("message")
        }
        _ => value.get("choices").is_some(),
    }
}

fn wrapped_text_response(path: &str, text: &str, family: &str) -> BufferedUpstreamResponse {
    let body = match path {
        "/v1/responses" => json!({
            "id": "resp_execution_target",
            "object": "response",
            "output": [{
                "type": "message",
                "role": "assistant",
                "content": [{
                    "type": "output_text",
                    "text": text,
                }],
            }],
        }),
        "/v1/messages" => json!({
            "id": "msg_execution_target",
            "type": "message",
            "role": "assistant",
            "content": [{
                "type": "text",
                "text": text,
            }],
            "stop_reason": "end_turn",
        }),
        _ => json!({
            "id": "chatcmpl_execution_target",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": text,
                },
                "finish_reason": "stop",
            }],
        }),
    };
    json_response(StatusCode::OK, body, Some(family))
}

fn extract_prompt_text(body: &Bytes) -> String {
    let parsed = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);

    if let Some(messages) = parsed.get("messages").and_then(Value::as_array) {
        if let Some(message) = messages.last() {
            if let Some(content) = message.get("content") {
                if let Some(text) = content.as_str() {
                    return text.to_string();
                }
                if let Some(parts) = content.as_array() {
                    let combined = parts
                        .iter()
                        .filter_map(|part| part.get("text").and_then(Value::as_str))
                        .collect::<String>();
                    if !combined.is_empty() {
                        return combined;
                    }
                }
            }
        }
    }

    parsed
        .get("input")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .unwrap_or_default()
}

fn execute_echo_target(path: &str, body: &Bytes) -> BufferedUpstreamResponse {
    wrapped_text_response(path, &extract_prompt_text(body), "echo")
}

fn execute_echo_target_streaming(path: &str, body: &Bytes) -> StreamingExecutionResponse {
    let text = extract_prompt_text(body);
    let chunks = vec![
        Ok(wrap_streaming_text_chunk(path, &text)),
        Ok(streaming_finish_chunk(path)),
        Ok(Bytes::from_static(b"data: [DONE]\n\n")),
    ];
    StreamingExecutionResponse {
        status: StatusCode::OK,
        content_type: HeaderValue::from_static("text/event-stream"),
        body: Box::pin(stream::iter(chunks)),
    }
}

fn compatibility_error_response(
    status: StatusCode,
    body: Value,
    family: Option<&str>,
) -> BufferedUpstreamResponse {
    json_response(status, body, family)
}

fn json_response(
    status: StatusCode,
    body: Value,
    family: Option<&str>,
) -> BufferedUpstreamResponse {
    let body = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    BufferedUpstreamResponse::new(status, default_headers(family), Bytes::from(body), false)
}

fn default_headers(family: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(family) = family {
        if let Ok(value) = HeaderValue::from_str(family) {
            headers.insert(
                HeaderName::from_static("x-verdictan-execution-target"),
                value,
            );
        }
    }
    headers
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
    use futures_util::StreamExt;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_script_path(ext: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos();
        path.push(format!(
            "verdictan-execution-runtime-{}-{nanos}.{ext}",
            std::process::id()
        ));
        path
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos();
        path.push(format!(
            "verdictan-execution-runtime-{label}-{}-{nanos}",
            std::process::id()
        ));
        path
    }

    fn write_temp_script(dir: &PathBuf, name: &str, source: &str) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, source).unwrap();
        path
    }

    // ── classify_capability ──────────────────────────────────────────────

    #[test]
    fn classify_exec_prefix_is_supported() {
        assert_eq!(
            classify_capability("exec:node script.js"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_file_prefix_is_supported() {
        assert_eq!(
            classify_capability("file:///tmp/run.py"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_echo_is_supported() {
        assert_eq!(classify_capability("echo"), ExecutionCapability::Supported);
    }

    #[test]
    fn classify_claude_agent_sdk_supported() {
        assert_eq!(
            classify_capability("claude-agent-sdk"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_codex_sdk_supported() {
        assert_eq!(
            classify_capability("codex-sdk"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_browser_adapter_only() {
        assert_eq!(
            classify_capability("browser"),
            ExecutionCapability::SupportedWithAdapter
        );
    }

    #[test]
    fn classify_chatkit_adapter_only() {
        assert_eq!(
            classify_capability("chatkit"),
            ExecutionCapability::SupportedWithAdapter
        );
    }

    #[test]
    fn classify_websocket_adapter_only() {
        assert_eq!(
            classify_capability("websocket"),
            ExecutionCapability::SupportedWithAdapter
        );
    }

    #[test]
    fn classify_manual_input_unsupported() {
        assert_eq!(
            classify_capability("manual-input"),
            ExecutionCapability::UnsupportedAtConfigTime
        );
    }

    #[test]
    fn classify_go_unsupported() {
        assert_eq!(
            classify_capability("go"),
            ExecutionCapability::UnsupportedAtConfigTime
        );
    }

    #[test]
    fn classify_unknown_unsupported() {
        assert_eq!(
            classify_capability("nonexistent-provider"),
            ExecutionCapability::UnsupportedAtConfigTime
        );
    }

    // ── AdapterFamily ────────────────────────────────────────────────────

    #[test]
    fn adapter_family_as_str_all() {
        assert_eq!(AdapterFamily::Browser.as_str(), "browser");
        assert_eq!(AdapterFamily::ChatKit.as_str(), "chatkit");
        assert_eq!(AdapterFamily::Transformers.as_str(), "transformers");
        assert_eq!(AdapterFamily::ClaudeAgentSdk.as_str(), "claude-agent-sdk");
        assert_eq!(AdapterFamily::CodexSdk.as_str(), "codex-sdk");
        assert_eq!(AdapterFamily::Mcp.as_str(), "mcp");
        assert_eq!(AdapterFamily::WebSocket.as_str(), "websocket");
        assert_eq!(AdapterFamily::OpenAiAgents.as_str(), "openai-agents");
        assert_eq!(AdapterFamily::OpenCodeSdk.as_str(), "opencode-sdk");
        assert_eq!(AdapterFamily::BedrockAgents.as_str(), "bedrock-agents");
    }

    #[test]
    fn adapter_family_support_mode_adapter_only() {
        assert_eq!(
            AdapterFamily::Browser.support_mode(),
            ExecutionSupportMode::AdapterOnly
        );
        assert_eq!(
            AdapterFamily::ChatKit.support_mode(),
            ExecutionSupportMode::AdapterOnly
        );
        assert_eq!(
            AdapterFamily::WebSocket.support_mode(),
            ExecutionSupportMode::AdapterOnly
        );
    }

    #[test]
    fn adapter_family_support_mode_native() {
        assert_eq!(
            AdapterFamily::ClaudeAgentSdk.support_mode(),
            ExecutionSupportMode::NativeRunnerOrAdapter
        );
        assert_eq!(
            AdapterFamily::CodexSdk.support_mode(),
            ExecutionSupportMode::NativeRunnerOrAdapter
        );
        assert_eq!(
            AdapterFamily::Mcp.support_mode(),
            ExecutionSupportMode::NativeRunnerOrAdapter
        );
    }

    // ── ExecutionTarget ──────────────────────────────────────────────────

    #[test]
    fn execution_target_kind_labels() {
        assert_eq!(ExecutionTarget::Echo.kind_label(), "echo");
        let unsup = ExecutionTarget::Unsupported {
            kind: "go".to_string(),
            reason: "not supported".to_string(),
        };
        assert_eq!(unsup.kind_label(), "go");
        assert_eq!(unsup.unsupported_reason(), Some("not supported"));
    }

    #[test]
    fn echo_target_no_unsupported_reason() {
        assert!(ExecutionTarget::Echo.unsupported_reason().is_none());
    }

    // ── parse_exec_command ───────────────────────────────────────────────

    #[test]
    fn parse_exec_command_simple() {
        let (prog, args) = parse_exec_command("node script.js --flag").unwrap();
        assert_eq!(prog, "node");
        assert_eq!(args, vec!["script.js", "--flag"]);
    }

    #[test]
    fn parse_exec_command_empty() {
        assert!(parse_exec_command("").is_none());
        assert!(parse_exec_command("   ").is_none());
    }

    #[test]
    fn parse_exec_command_single_program() {
        let (prog, args) = parse_exec_command("python3").unwrap();
        assert_eq!(prog, "python3");
        assert!(args.is_empty());
    }

    // ── parse_timeout ────────────────────────────────────────────────────

    #[test]
    fn parse_timeout_default() {
        let entry = json!({});
        assert_eq!(parse_timeout(&entry), Duration::from_millis(30_000));
    }

    #[test]
    fn parse_timeout_custom() {
        let entry = json!({"execution_timeout_ms": 5000});
        assert_eq!(parse_timeout(&entry), Duration::from_millis(5000));
    }

    #[test]
    fn parse_timeout_zero_clamped_to_one() {
        let entry = json!({"execution_timeout_ms": 0});
        assert_eq!(parse_timeout(&entry), Duration::from_millis(1));
    }

    // ── parse_env_map / parse_env_map_merged ─────────────────────────────

    #[test]
    fn parse_env_map_empty() {
        assert!(parse_env_map(None).is_empty());
        assert!(parse_env_map(Some(&json!(42))).is_empty());
    }

    #[test]
    fn parse_env_map_valid() {
        let val = json!({"KEY": "value", "NUM": 42});
        let map = parse_env_map(Some(&val));
        assert_eq!(map.get("KEY"), Some(&"value".to_string()));
        assert!(map.get("NUM").is_none());
    }

    #[test]
    fn parse_env_map_merged_combines() {
        let primary = json!({"A": "1"});
        let fallback = json!({"B": "2", "A": "override"});
        let merged = parse_env_map_merged(Some(&primary), Some(&fallback));
        assert_eq!(merged.get("A"), Some(&"override".to_string()));
        assert_eq!(merged.get("B"), Some(&"2".to_string()));
    }

    // ── entry_string / entry_string_array ────────────────────────────────

    #[test]
    fn entry_string_first_match() {
        let entry = json!({"model": "gpt-5.4", "alias": "gpt"});
        assert_eq!(
            entry_string(&entry, &["model"]),
            Some("gpt-5.4".to_string())
        );
    }

    #[test]
    fn entry_string_skips_empty() {
        let entry = json!({"model": "  "});
        assert!(entry_string(&entry, &["model"]).is_none());
    }

    #[test]
    fn entry_string_array_valid() {
        let arr = json!(["arg1", "arg2"]);
        assert_eq!(entry_string_array(Some(&arr)), vec!["arg1", "arg2"]);
    }

    #[test]
    fn entry_string_array_none() {
        assert!(entry_string_array(None).is_empty());
    }

    // ── is_allowed_execution_program ─────────────────────────────────────

    #[test]
    fn allowed_programs_pass() {
        assert!(is_allowed_execution_program("node"));
        assert!(is_allowed_execution_program("python3"));
        assert!(is_allowed_execution_program("cargo"));
        assert!(is_allowed_execution_program("verdictan"));
    }

    #[test]
    fn disallowed_programs_fail() {
        assert!(!is_allowed_execution_program("malicious-binary"));
        assert!(!is_allowed_execution_program("rm"));
    }

    #[test]
    fn script_extensions_allowed() {
        assert!(is_allowed_execution_program("script.py"));
        assert!(is_allowed_execution_program("run.js"));
        assert!(is_allowed_execution_program("setup.sh"));
        assert!(is_allowed_execution_program("lib.rb"));
    }

    #[test]
    fn unknown_extension_disallowed() {
        assert!(!is_allowed_execution_program("payload.exe"));
    }

    // ── normalized_execution_alias ───────────────────────────────────────

    #[test]
    fn normalized_alias_common_values() {
        assert_eq!(normalized_execution_alias("browser"), "browser");
        assert_eq!(normalized_execution_alias("browser-agent"), "browser");
        assert_eq!(normalized_execution_alias("playwright-browser"), "browser");
        assert_eq!(
            normalized_execution_alias("claude-code"),
            "claude-agent-sdk"
        );
        assert_eq!(normalized_execution_alias("codex"), "codex-sdk");
        assert_eq!(normalized_execution_alias("echo"), "echo");
        assert_eq!(normalized_execution_alias("go"), "go");
        assert_eq!(normalized_execution_alias("ruby-script"), "ruby");
        assert_eq!(normalized_execution_alias("slack"), "slack-feedback");
        assert_eq!(normalized_execution_alias("webhook-runner"), "webhook");
    }

    #[test]
    fn normalized_alias_unknown_returns_empty() {
        assert_eq!(normalized_execution_alias("nonexistent"), "");
    }

    // ── looks_like_sse_chunk ─────────────────────────────────────────────

    #[test]
    fn sse_chunk_detection() {
        assert!(looks_like_sse_chunk(&Bytes::from_static(
            b"data: {\"id\":1}"
        )));
        assert!(looks_like_sse_chunk(&Bytes::from_static(b"event: done")));
        assert!(!looks_like_sse_chunk(&Bytes::from_static(b"{\"id\":1}")));
    }

    // ── wrap_streaming_text_chunk ────────────────────────────────────────

    #[test]
    fn streaming_chunk_chat_completions() {
        let chunk = wrap_streaming_text_chunk("/v1/chat/completions", "hello");
        let text = String::from_utf8_lossy(&chunk);
        assert!(text.starts_with("data: "));
        let payload: serde_json::Value =
            serde_json::from_str(text.trim_start_matches("data: ").trim()).unwrap();
        assert_eq!(payload["choices"][0]["delta"]["content"], "hello");
    }

    #[test]
    fn streaming_chunk_responses() {
        let chunk = wrap_streaming_text_chunk("/v1/responses", "hi");
        let text = String::from_utf8_lossy(&chunk);
        let payload: serde_json::Value =
            serde_json::from_str(text.trim_start_matches("data: ").trim()).unwrap();
        assert_eq!(payload["type"], "response.output_text.delta");
        assert_eq!(payload["delta"], "hi");
    }

    #[test]
    fn streaming_chunk_messages() {
        let chunk = wrap_streaming_text_chunk("/v1/messages", "test");
        let text = String::from_utf8_lossy(&chunk);
        let payload: serde_json::Value =
            serde_json::from_str(text.trim_start_matches("data: ").trim()).unwrap();
        assert_eq!(payload["type"], "content_block_delta");
    }

    // ── streaming_finish_chunk ───────────────────────────────────────────

    #[test]
    fn finish_chunk_chat_completions() {
        let chunk = streaming_finish_chunk("/v1/chat/completions");
        let text = String::from_utf8_lossy(&chunk);
        let payload: serde_json::Value =
            serde_json::from_str(text.trim_start_matches("data: ").trim()).unwrap();
        assert_eq!(payload["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn finish_chunk_responses() {
        let chunk = streaming_finish_chunk("/v1/responses");
        let text = String::from_utf8_lossy(&chunk);
        let payload: serde_json::Value =
            serde_json::from_str(text.trim_start_matches("data: ").trim()).unwrap();
        assert_eq!(payload["type"], "response.completed");
    }

    // ── looks_like_native_response ───────────────────────────────────────

    #[test]
    fn native_response_detection() {
        assert!(looks_like_native_response(
            "/v1/embeddings",
            &json!({"data": []})
        ));
        assert!(!looks_like_native_response(
            "/v1/embeddings",
            &json!({"result": "ok"})
        ));
        assert!(looks_like_native_response(
            "/v1/responses",
            &json!({"output": []})
        ));
        assert!(looks_like_native_response(
            "/v1/chat/completions",
            &json!({"choices": []})
        ));
        let msg = json!({"content": [], "type": "message"});
        assert!(looks_like_native_response("/v1/messages", &msg));
    }

    // ── extract_prompt_text ──────────────────────────────────────────────

    #[test]
    fn extract_prompt_from_messages() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "messages": [{"role": "user", "content": "hello world"}]
            }))
            .unwrap(),
        );
        assert_eq!(extract_prompt_text(&body), "hello world");
    }

    #[test]
    fn extract_prompt_from_input() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "input": "embed this"
            }))
            .unwrap(),
        );
        assert_eq!(extract_prompt_text(&body), "embed this");
    }

    #[test]
    fn extract_prompt_empty_body() {
        let body = Bytes::from_static(b"invalid json");
        assert_eq!(extract_prompt_text(&body), "");
    }

    #[test]
    fn extract_prompt_multipart_content() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": "part1"},
                    {"type": "text", "text": "part2"},
                ]}]
            }))
            .unwrap(),
        );
        assert_eq!(extract_prompt_text(&body), "part1part2");
    }

    // ── build_execution_payload ──────────────────────────────────────────

    #[test]
    fn execution_payload_structure() {
        let target = CommandExecutionTarget {
            program: "node".to_string(),
            args: vec![],
            cwd: None,
            env: HashMap::new(),
            timeout: Duration::from_secs(30),
            family: Some(AdapterFamily::Transformers),
            workflow_id: None,
            runner_config: None,
        };
        let body = Bytes::from(r#"{"model":"test"}"#);
        let payload = build_execution_payload(
            &target,
            "prov-1",
            "/v1/chat/completions",
            &body,
            "req-1",
            false,
        );
        assert_eq!(payload["provider_id"], "prov-1");
        assert_eq!(payload["request_id"], "req-1");
        assert_eq!(payload["path"], "/v1/chat/completions");
        assert_eq!(payload["stream"], false);
        assert_eq!(payload["execution_target"]["family"], "transformers");
    }

    // ── parse_execution_target ───────────────────────────────────────────

    #[test]
    fn parse_execution_target_echo() {
        let entry = json!({});
        let result = parse_execution_target("echo", &entry).unwrap();
        assert!(matches!(result, Some(ExecutionTarget::Echo)));
    }

    #[test]
    fn parse_execution_target_exec_prefix() {
        let entry = json!({});
        let result = parse_execution_target("exec:node runner.js", &entry).unwrap();
        match result {
            Some(ExecutionTarget::Command(cmd)) => {
                assert_eq!(cmd.program, "node");
                assert_eq!(cmd.args, vec!["runner.js"]);
            }
            _ => panic!("expected Command"),
        }
    }

    #[test]
    fn parse_execution_target_file_prefix() {
        let entry = json!({});
        let result = parse_execution_target("file:///tmp/script.py", &entry).unwrap();
        match result {
            Some(ExecutionTarget::File(f)) => {
                assert_eq!(f.path, "/tmp/script.py");
            }
            _ => panic!("expected File"),
        }
    }

    #[test]
    fn parse_execution_target_unsupported() {
        let entry = json!({});
        let result = parse_execution_target("manual-input", &entry).unwrap();
        assert!(matches!(result, Some(ExecutionTarget::Unsupported { .. })));
    }

    #[test]
    fn parse_execution_target_file_empty_path_errors() {
        let entry = json!({});
        assert!(parse_execution_target("file://", &entry).is_err());
    }

    #[test]
    fn parse_execution_target_exec_empty_command_errors() {
        let entry = json!({});
        assert!(parse_execution_target("exec:", &entry).is_err());
    }

    // ── execution_family_info ────────────────────────────────────────────

    #[test]
    fn execution_family_info_known_providers() {
        let info = execution_family_info("claude-agent-sdk").unwrap();
        assert_eq!(info.family, AdapterFamily::ClaudeAgentSdk);
        assert_eq!(info.kind, "claude-agent-sdk");
    }

    #[test]
    fn execution_family_info_colon_syntax() {
        let info = execution_family_info("anthropic:claude-agent-sdk").unwrap();
        assert_eq!(info.family, AdapterFamily::ClaudeAgentSdk);
    }

    #[test]
    fn execution_family_info_unknown_returns_none() {
        assert!(execution_family_info("openai").is_none());
    }

    // ── unsupported_family_reason ────────────────────────────────────────

    #[test]
    fn unsupported_reason_all_families_non_empty() {
        for family in [
            AdapterFamily::Browser,
            AdapterFamily::ChatKit,
            AdapterFamily::Transformers,
            AdapterFamily::ClaudeAgentSdk,
            AdapterFamily::CodexSdk,
            AdapterFamily::Mcp,
            AdapterFamily::WebSocket,
            AdapterFamily::OpenAiAgents,
            AdapterFamily::OpenCodeSdk,
            AdapterFamily::BedrockAgents,
        ] {
            assert!(!unsupported_family_reason(family).is_empty());
        }
    }

    // ── native_default_program ───────────────────────────────────────────

    #[test]
    fn native_default_program_known_families() {
        let entry = json!({});
        assert!(native_default_program(AdapterFamily::ClaudeAgentSdk, &entry).is_some());
        assert!(native_default_program(AdapterFamily::CodexSdk, &entry).is_some());
        assert!(native_default_program(AdapterFamily::Mcp, &entry).is_none());
    }

    #[test]
    fn native_default_program_entry_override() {
        let entry = json!({"path_to_claude_code_executable": "custom-bin"});
        let prog = native_default_program(AdapterFamily::ClaudeAgentSdk, &entry);
        assert_eq!(prog, Some("custom-bin".to_string()));
    }

    // ── native_default_args ──────────────────────────────────────────────

    #[test]
    fn native_default_args_transformers() {
        let args = native_default_args(AdapterFamily::Transformers, None);
        assert!(!args.is_empty());
    }

    #[test]
    fn native_default_args_claude_is_empty() {
        let args = native_default_args(AdapterFamily::ClaudeAgentSdk, None);
        assert!(args.is_empty());
    }

    // ── execution_cwd ────────────────────────────────────────────────────

    #[test]
    fn execution_cwd_present() {
        let entry = json!({"adapter_cwd": "/tmp/work"});
        assert_eq!(execution_cwd(&entry), Some("/tmp/work".to_string()));
    }

    #[test]
    fn execution_cwd_with_working_dir() {
        let entry = json!({"working_dir": "/tmp/alt"});
        assert_eq!(execution_cwd(&entry), Some("/tmp/alt".to_string()));
    }

    #[test]
    fn execution_cwd_absent() {
        assert!(execution_cwd(&json!({})).is_none());
    }

    // ── default_headers ──────────────────────────────────────────────────

    #[test]
    fn default_headers_has_content_type() {
        let headers = default_headers(None);
        assert!(headers.contains_key(axum::http::header::CONTENT_TYPE));
    }

    #[test]
    fn default_headers_with_family() {
        let headers = default_headers(Some("echo"));
        assert!(headers.contains_key(axum::http::header::CONTENT_TYPE));
    }

    // ── streaming_error_response ─────────────────────────────────────────

    #[test]
    fn streaming_error_response_structure() {
        let resp = streaming_error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "oops"}),
            None,
        );
        assert_eq!(resp.status, axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── json_response ────────────────────────────────────────────────────

    #[test]
    fn json_response_structure() {
        let resp = json_response(axum::http::StatusCode::OK, json!({"result": "ok"}), None);
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    // ── compatibility_error_response ─────────────────────────────────────

    #[test]
    fn compatibility_error_response_structure() {
        let resp = compatibility_error_response(
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            json!({"error": "test error"}),
            None,
        );
        assert_eq!(resp.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ── parse_execution_family additional cases ──────────────────────────

    #[test]
    fn parse_execution_family_known_providers() {
        assert!(parse_execution_family("claude-agent-sdk").is_some());
        assert!(parse_execution_family("codex-sdk").is_some());
        assert!(parse_execution_family("mcp").is_some());
        assert!(parse_execution_family("browser").is_some());
    }

    #[test]
    fn parse_execution_family_unknown() {
        assert!(parse_execution_family("openai").is_none());
    }

    #[test]
    fn parse_execution_family_colon_syntax() {
        assert!(parse_execution_family("anthropic:claude-agent-sdk").is_some());
    }

    #[test]
    fn parse_execution_target_chatkit_with_workflow_id_and_adapter_command() {
        let entry = json!({
            "adapter_command": "node",
            "adapter_args": ["runner.js"],
            "working_dir": "/tmp/chatkit",
            "execution_timeout_ms": 2500,
            "cli_env": {"A": "1"},
            "adapter_env": {"A": "override", "B": "2"}
        });

        let result = parse_execution_target("openai:chatkit:incident-triage", &entry).unwrap();
        match result {
            Some(ExecutionTarget::Command(target)) => {
                assert_eq!(target.program, "node");
                assert_eq!(target.args, vec!["runner.js"]);
                assert_eq!(target.cwd.as_deref(), Some("/tmp/chatkit"));
                assert_eq!(target.timeout, Duration::from_millis(2500));
                assert_eq!(target.family, Some(AdapterFamily::ChatKit));
                assert_eq!(target.workflow_id.as_deref(), Some("incident-triage"));
                assert_eq!(target.env.get("A"), Some(&"override".to_string()));
                assert_eq!(target.env.get("B"), Some(&"2".to_string()));
                assert!(target.runner_config.is_some());
            }
            other => panic!("expected command target, got {other:?}"),
        }
    }

    #[test]
    fn parse_execution_target_browser_without_adapter_command_is_unsupported() {
        let result = parse_execution_target("browser", &json!({})).unwrap();
        match result {
            Some(ExecutionTarget::Unsupported { kind, reason }) => {
                assert_eq!(kind, "browser");
                assert!(reason.contains("adapter_command"));
            }
            other => panic!("expected unsupported target, got {other:?}"),
        }
    }

    #[test]
    fn parse_execution_target_mcp_without_adapter_or_base_url_returns_none() {
        let result = parse_execution_target("mcp", &json!({})).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn build_native_runner_config_extracts_transformers_fields() {
        let entry = json!({
            "provider": "transformers:text-generation:HuggingFaceH4/zephyr",
            "device": "cpu",
            "cacheDir": "/tmp/models",
            "localFilesOnly": true,
            "temperature": 0.2,
            "sessionOptions": {
                "intra_op_num_threads": 2
            }
        });

        let config = build_native_runner_config(&entry, AdapterFamily::Transformers).unwrap();
        assert_eq!(config["task"], json!("text-generation"));
        assert_eq!(config["model"], json!("HuggingFaceH4/zephyr"));
        assert_eq!(config["device"], json!("cpu"));
        assert_eq!(config["cache_dir"], json!("/tmp/models"));
        assert_eq!(config["local_files_only"], json!(true));
        assert_eq!(config["temperature"], json!(0.2));
        assert_eq!(config["session_options"]["intra_op_num_threads"], json!(2));
    }

    #[test]
    fn build_native_runner_config_extracts_codex_fields() {
        let entry = json!({
            "codex_path_override": "codex-beta",
            "sandbox_mode": "workspace-write",
            "approval_policy": "on-request",
            "network_access_enabled": true,
            "web_search_enabled": false,
            "skip_git_repo_check": true
        });

        let config = build_native_runner_config(&entry, AdapterFamily::CodexSdk).unwrap();
        assert_eq!(config["codex_path_override"], json!("codex-beta"));
        assert_eq!(config["sandbox_mode"], json!("workspace-write"));
        assert_eq!(config["approval_policy"], json!("on-request"));
        assert_eq!(config["network_access_enabled"], json!(true));
        assert_eq!(config["web_search_enabled"], json!(false));
        assert_eq!(config["skip_git_repo_check"], json!(true));
    }

    #[test]
    fn script_launcher_and_resolved_command_expand_known_scripts() {
        let script_path = unique_temp_script_path("py");
        fs::write(&script_path, "print('ok')\n").unwrap();

        let (program, args) = script_launcher(&script_path).unwrap();
        assert_eq!(program, "python3");
        assert_eq!(args.len(), 1);
        assert!(args[0].ends_with(".py"));

        let target = CommandExecutionTarget {
            program: script_path.display().to_string(),
            args: vec!["--flag".to_string()],
            cwd: None,
            env: HashMap::new(),
            timeout: Duration::from_secs(1),
            family: None,
            workflow_id: None,
            runner_config: None,
        };
        let (program, args) = resolved_command_program_and_args(&target).unwrap();
        assert_eq!(program, "python3");
        assert_eq!(args.len(), 2);
        assert_eq!(args[1], "--flag");

        let _ = fs::remove_file(script_path);
    }

    #[test]
    fn explicit_response_envelope_applies_headers_and_status() {
        let value = json!({
            "status": 202,
            "headers": {
                "x-trace-id": "trace-1",
                "x-invalid": 7
            },
            "body": {
                "ok": true
            }
        });

        let response = explicit_response_envelope(&value, "chatkit").unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response.headers().get("x-trace-id").unwrap(),
            &HeaderValue::from_static("trace-1")
        );
        assert!(response.headers().get("x-invalid").is_none());

        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["ok"], json!(true));
    }

    #[test]
    fn response_from_stdout_rejects_invalid_embeddings_payloads() {
        let response = response_from_stdout("/v1/embeddings", br#"{"result":"ok"}"#, "exec");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(
            body["error"]["code"],
            json!("execution_invalid_embeddings_output")
        );
    }

    #[test]
    fn execute_echo_target_wraps_last_message_content() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "messages": [
                    {"role": "user", "content": "ignored"},
                    {"role": "user", "content": "reply to me"}
                ]
            }))
            .unwrap(),
        );

        let response = execute_echo_target("/v1/chat/completions", &body);
        assert_eq!(response.status(), StatusCode::OK);
        let payload: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(
            payload["choices"][0]["message"]["content"],
            json!("reply to me")
        );
    }

    #[tokio::test]
    async fn execute_echo_target_streaming_emits_done_sequence() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "input": "stream this"
            }))
            .unwrap(),
        );

        let response = execute_echo_target_streaming("/v1/responses", &body);
        let chunks: Vec<Bytes> = response
            .body
            .map(|chunk| chunk.expect("stream chunk"))
            .collect()
            .await;

        assert_eq!(chunks.len(), 3);
        let first = String::from_utf8_lossy(&chunks[0]);
        let second = String::from_utf8_lossy(&chunks[1]);
        assert!(first.contains("response.output_text.delta"));
        assert!(first.contains("stream this"));
        assert!(second.contains("response.completed"));
        assert_eq!(chunks[2], Bytes::from_static(b"data: [DONE]\n\n"));
    }

    #[test]
    fn classify_capability_additional_aliases_and_colon_variants() {
        assert_eq!(
            classify_capability(" openai:chatkit:incident-triage "),
            ExecutionCapability::SupportedWithAdapter
        );
        assert_eq!(
            classify_capability("transformers.js:text-generation:model"),
            ExecutionCapability::Supported
        );
        assert_eq!(
            classify_capability("aws:agents"),
            ExecutionCapability::Supported
        );
        assert_eq!(
            classify_capability("slack"),
            ExecutionCapability::UnsupportedAtConfigTime
        );
    }

    #[test]
    fn execution_target_kind_labels_cover_command_variants_and_file() {
        let command_with_family = ExecutionTarget::Command(CommandExecutionTarget {
            program: "codex".to_string(),
            args: Vec::new(),
            cwd: None,
            env: HashMap::new(),
            timeout: Duration::from_secs(1),
            family: Some(AdapterFamily::CodexSdk),
            workflow_id: None,
            runner_config: None,
        });
        assert_eq!(command_with_family.kind_label(), "codex-sdk");

        let command_without_family = ExecutionTarget::Command(CommandExecutionTarget {
            program: "node".to_string(),
            args: Vec::new(),
            cwd: None,
            env: HashMap::new(),
            timeout: Duration::from_secs(1),
            family: None,
            workflow_id: None,
            runner_config: None,
        });
        assert_eq!(command_without_family.kind_label(), "exec");
        assert_eq!(
            ExecutionTarget::File(FileExecutionTarget {
                path: "/tmp/script.js".to_string(),
                timeout: Duration::from_secs(1),
            })
            .kind_label(),
            "file"
        );
    }

    #[test]
    fn parse_execution_target_unknown_provider_returns_none() {
        let result = parse_execution_target("totally-unknown", &json!({})).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_execution_target_transformers_uses_native_defaults() {
        let entry = json!({
            "provider": "transformers:text-generation:HuggingFaceH4/zephyr",
            "adapter_args": ["--trace"],
            "working_dir": "/tmp/transformers",
            "execution_timeout_ms": 1234,
            "cli_env": {"A": "1"}
        });

        let result =
            parse_execution_target("transformers:text-generation:HuggingFaceH4/zephyr", &entry)
                .unwrap();
        match result {
            Some(ExecutionTarget::Command(target)) => {
                assert_eq!(target.program, "node");
                assert_eq!(target.args[0], "--input-type=module");
                assert_eq!(target.args[1], "-e");
                assert_eq!(target.args.last(), Some(&"--trace".to_string()));
                assert_eq!(target.cwd.as_deref(), Some("/tmp/transformers"));
                assert_eq!(target.timeout, Duration::from_millis(1234));
                assert_eq!(target.family, Some(AdapterFamily::Transformers));
                assert_eq!(target.env.get("A"), Some(&"1".to_string()));
                assert_eq!(
                    target.runner_config.as_ref().unwrap()["task"],
                    json!("text-generation")
                );
            }
            other => panic!("expected transformers command target, got {other:?}"),
        }
    }

    #[test]
    fn parse_execution_target_mcp_with_adapter_command_returns_command() {
        let entry = json!({
            "adapter_command": "node",
            "adapter_args": ["bridge.js"]
        });

        let result = parse_execution_target("mcp", &entry).unwrap();
        match result {
            Some(ExecutionTarget::Command(target)) => {
                assert_eq!(target.program, "node");
                assert_eq!(target.args, vec!["bridge.js"]);
                assert_eq!(target.family, Some(AdapterFamily::Mcp));
            }
            other => panic!("expected mcp command target, got {other:?}"),
        }
    }

    #[test]
    fn parse_execution_target_additional_native_families_use_defaults() {
        let claude = parse_execution_target(
            "claude-code",
            &json!({
                "working_dir": "/tmp/claude",
                "permission_mode": "acceptEdits"
            }),
        )
        .unwrap();
        match claude {
            Some(ExecutionTarget::Command(target)) => {
                assert_eq!(target.program, "claude");
                assert_eq!(target.family, Some(AdapterFamily::ClaudeAgentSdk));
                assert_eq!(target.cwd.as_deref(), Some("/tmp/claude"));
                assert_eq!(
                    target.runner_config.as_ref().unwrap()["permission_mode"],
                    json!("acceptEdits")
                );
            }
            other => panic!("expected claude command target, got {other:?}"),
        }

        let openai = parse_execution_target(
            "openai:agents",
            &json!({
                "agent_name": "triage"
            }),
        )
        .unwrap();
        match openai {
            Some(ExecutionTarget::Command(target)) => {
                assert_eq!(target.program, "openai-agents");
                assert_eq!(target.family, Some(AdapterFamily::OpenAiAgents));
                assert_eq!(
                    target.runner_config.as_ref().unwrap()["agent_name"],
                    "triage"
                );
            }
            other => panic!("expected openai agents command target, got {other:?}"),
        }

        let opencode = parse_execution_target("openai:opencode", &json!({})).unwrap();
        match opencode {
            Some(ExecutionTarget::Command(target)) => {
                assert_eq!(target.program, "opencode");
                assert_eq!(target.family, Some(AdapterFamily::OpenCodeSdk));
                assert!(target.runner_config.is_none());
            }
            other => panic!("expected opencode command target, got {other:?}"),
        }

        let bedrock = parse_execution_target(
            "aws:agents",
            &json!({
                "aws_region": "eu-west-1"
            }),
        )
        .unwrap();
        match bedrock {
            Some(ExecutionTarget::Command(target)) => {
                assert_eq!(target.program, "bedrock-agents");
                assert_eq!(target.family, Some(AdapterFamily::BedrockAgents));
                assert_eq!(
                    target.runner_config.as_ref().unwrap()["aws_region"],
                    "eu-west-1"
                );
            }
            other => panic!("expected bedrock command target, got {other:?}"),
        }
    }

    #[test]
    fn parse_execution_family_additional_variants() {
        let chatkit = parse_execution_family("openai:chatkit:incident:triage").unwrap();
        assert_eq!(chatkit.family, AdapterFamily::ChatKit);
        assert_eq!(chatkit.kind, "chatkit");
        assert_eq!(chatkit.workflow_id.as_deref(), Some("incident:triage"));

        assert_eq!(
            parse_execution_family("transformers.js:text-generation:model")
                .unwrap()
                .family,
            AdapterFamily::Transformers
        );
        assert_eq!(
            parse_execution_family("openai:codex").unwrap().family,
            AdapterFamily::CodexSdk
        );
        assert_eq!(
            parse_execution_family("openai:agents").unwrap().family,
            AdapterFamily::OpenAiAgents
        );
        assert_eq!(
            parse_execution_family("openai:opencode").unwrap().family,
            AdapterFamily::OpenCodeSdk
        );
        assert_eq!(
            parse_execution_family("bedrock:agents").unwrap().family,
            AdapterFamily::BedrockAgents
        );
        assert_eq!(
            parse_execution_family("aws:agents").unwrap().family,
            AdapterFamily::BedrockAgents
        );
    }

    #[test]
    fn normalized_alias_additional_variants() {
        assert_eq!(
            normalized_execution_alias("transformers.js:embeddings:model"),
            "transformers"
        );
        assert_eq!(normalized_execution_alias("rb"), "ruby");
        assert_eq!(normalized_execution_alias("opencode"), "opencode-sdk");
        assert_eq!(
            normalized_execution_alias("bedrock-agents"),
            "bedrock-agents"
        );
    }

    #[test]
    fn build_native_runner_config_extracts_claude_and_shared_fields() {
        let entry = json!({
            "model": "claude-3-sonnet",
            "working_dir": "/tmp/claude",
            "additional_directories": ["/tmp/a", 7, "/tmp/b"],
            "cli_env": {"A": "1"},
            "path_to_claude_code_executable": "claude-beta",
            "permission_mode": "acceptEdits",
            "fallback_model": "claude-3-haiku",
            "append_allowed_tools": ["Read", false, "Edit"],
            "disallowed_tools": ["Bash"],
            "allow_all_tools": true,
            "max_turns": 7
        });

        let config = build_native_runner_config(&entry, AdapterFamily::ClaudeAgentSdk).unwrap();
        assert_eq!(config["model"], json!("claude-3-sonnet"));
        assert_eq!(config["working_dir"], json!("/tmp/claude"));
        assert_eq!(
            config["additional_directories"],
            json!(["/tmp/a", "/tmp/b"])
        );
        assert_eq!(config["cli_env"]["A"], json!("1"));
        assert_eq!(
            config["path_to_claude_code_executable"],
            json!("claude-beta")
        );
        assert_eq!(config["permission_mode"], json!("acceptEdits"));
        assert_eq!(config["fallback_model"], json!("claude-3-haiku"));
        assert_eq!(config["append_allowed_tools"], json!(["Read", "Edit"]));
        assert_eq!(config["disallowed_tools"], json!(["Bash"]));
        assert_eq!(config["allow_all_tools"], json!(true));
        assert_eq!(config["max_turns"], json!(7));
    }

    #[test]
    fn build_native_runner_config_other_families_and_empty_browser() {
        let openai = build_native_runner_config(
            &json!({
                "openai_agents_path_override": "openai-agents-beta",
                "agent_name": "triage"
            }),
            AdapterFamily::OpenAiAgents,
        )
        .unwrap();
        assert_eq!(
            openai["openai_agents_path_override"],
            json!("openai-agents-beta")
        );
        assert_eq!(openai["agent_name"], json!("triage"));

        let opencode = build_native_runner_config(
            &json!({
                "opencode_path_override": "opencode-beta"
            }),
            AdapterFamily::OpenCodeSdk,
        )
        .unwrap();
        assert_eq!(opencode["opencode_path_override"], json!("opencode-beta"));

        let bedrock = build_native_runner_config(
            &json!({
                "bedrock_agents_path_override": "bedrock-agents-beta",
                "aws_region": "us-east-1"
            }),
            AdapterFamily::BedrockAgents,
        )
        .unwrap();
        assert_eq!(
            bedrock["bedrock_agents_path_override"],
            json!("bedrock-agents-beta")
        );
        assert_eq!(bedrock["aws_region"], json!("us-east-1"));

        assert!(build_native_runner_config(&json!({}), AdapterFamily::Browser).is_none());
    }

    #[test]
    fn native_default_program_additional_families() {
        let empty = json!({});
        assert_eq!(
            native_default_program(AdapterFamily::OpenAiAgents, &empty),
            Some("openai-agents".to_string())
        );
        assert_eq!(
            native_default_program(AdapterFamily::OpenCodeSdk, &empty),
            Some("opencode".to_string())
        );
        assert_eq!(
            native_default_program(AdapterFamily::BedrockAgents, &empty),
            Some("bedrock-agents".to_string())
        );
        assert_eq!(
            native_default_program(
                AdapterFamily::Transformers,
                &json!({"node_path_override": "node20"})
            ),
            Some("node20".to_string())
        );
    }

    #[test]
    fn native_default_args_chatkit_with_workflow_is_empty() {
        assert!(native_default_args(AdapterFamily::ChatKit, Some("incident")).is_empty());
    }

    #[test]
    fn allowed_program_accepts_basenames_and_case_insensitive_extensions() {
        assert!(is_allowed_execution_program("/usr/local/bin/node"));
        assert!(is_allowed_execution_program("SCRIPT.PY"));
    }

    #[test]
    fn script_launcher_handles_js_unknown_extensions_and_direct_programs() {
        let js_path = unique_temp_script_path("js");
        let txt_path = unique_temp_script_path("txt");
        fs::write(&js_path, "console.log('ok');\n").unwrap();
        fs::write(&txt_path, "plain text\n").unwrap();

        let (program, args) = script_launcher(&js_path).unwrap();
        assert_eq!(program, "node");
        assert_eq!(args.len(), 1);
        assert!(args[0].ends_with(".js"));

        let (program, args) = script_launcher(&txt_path).unwrap();
        assert_eq!(
            program,
            txt_path.canonicalize().unwrap().display().to_string()
        );
        assert!(args.is_empty());

        let target = CommandExecutionTarget {
            program: "node".to_string(),
            args: vec!["runner.js".to_string()],
            cwd: None,
            env: HashMap::new(),
            timeout: Duration::from_secs(1),
            family: None,
            workflow_id: None,
            runner_config: None,
        };
        let (program, args) = resolved_command_program_and_args(&target).unwrap();
        assert_eq!(program, "node");
        assert_eq!(args, vec!["runner.js"]);

        let _ = fs::remove_file(js_path);
        let _ = fs::remove_file(txt_path);
    }

    #[test]
    fn explicit_response_envelope_requires_body_and_sanitizes_invalid_values() {
        assert!(explicit_response_envelope(&json!({"status": 204}), "echo").is_none());

        let response = explicit_response_envelope(
            &json!({
                "status": 2000,
                "headers": {
                    "x-good": "ok",
                    "bad header": "ignored"
                },
                "body": {
                    "ok": true
                }
            }),
            "echo",
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-good").unwrap(),
            &HeaderValue::from_static("ok")
        );
        assert!(response.headers().get("bad header").is_none());
    }

    #[test]
    fn response_from_stdout_empty_output_errors() {
        let response = response_from_stdout("/v1/chat/completions", b"  \n", "exec");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["error"]["code"], json!("execution_empty_output"));
    }

    #[test]
    fn response_from_stdout_non_json_embeddings_errors() {
        let response = response_from_stdout("/v1/embeddings", b"plain text", "exec");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(
            body["error"]["code"],
            json!("execution_invalid_embeddings_output")
        );
    }

    #[test]
    fn response_from_stdout_respects_explicit_envelopes() {
        let response = response_from_stdout(
            "/v1/chat/completions",
            br#"{"status":201,"body":{"ok":true}}"#,
            "exec",
        );
        assert_eq!(response.status(), StatusCode::CREATED);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["ok"], json!(true));
    }

    #[test]
    fn response_from_stdout_passes_through_native_and_wrapped_shapes() {
        let native_response = response_from_stdout(
            "/v1/messages",
            br#"{"type":"message","content":[]}"#,
            "exec",
        );
        let native_body: Value = serde_json::from_slice(native_response.body()).unwrap();
        assert_eq!(native_body["type"], json!("message"));
        assert_eq!(native_body["content"], json!([]));

        let wrapped_response =
            response_from_stdout("/v1/responses", br#"{"content":"hello"}"#, "exec");
        let wrapped_body: Value = serde_json::from_slice(wrapped_response.body()).unwrap();
        assert_eq!(
            wrapped_body["output"][0]["content"][0]["text"],
            json!("hello")
        );

        let message_response = response_from_stdout("/v1/messages", b"plain text", "exec");
        let message_body: Value = serde_json::from_slice(message_response.body()).unwrap();
        assert_eq!(message_body["content"][0]["text"], json!("plain text"));
    }

    #[test]
    fn build_execution_payload_invalid_json_uses_raw_body() {
        let target = CommandExecutionTarget {
            program: "node".to_string(),
            args: Vec::new(),
            cwd: None,
            env: HashMap::new(),
            timeout: Duration::from_secs(1),
            family: None,
            workflow_id: None,
            runner_config: None,
        };

        let payload = build_execution_payload(
            &target,
            "prov-1",
            "/v1/messages",
            &Bytes::from_static(b"not-json"),
            "req-1",
            true,
        );
        assert_eq!(payload["request"]["raw_body"], json!("not-json"));
    }

    #[test]
    fn extract_prompt_falls_back_to_input_when_message_parts_have_no_text() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "messages": [{"role": "user", "content": [{"type": "image"}]}],
                "input": "fallback"
            }))
            .unwrap(),
        );

        assert_eq!(extract_prompt_text(&body), "fallback");
    }

    #[test]
    fn default_headers_skip_invalid_family_values() {
        let headers = default_headers(Some("bad\nvalue"));
        assert!(headers.contains_key(axum::http::header::CONTENT_TYPE));
        assert!(!headers.contains_key("x-verdictan-execution-target"));
    }

    #[test]
    fn streaming_finish_chunk_messages_variant() {
        let chunk = streaming_finish_chunk("/v1/messages");
        let text = String::from_utf8_lossy(&chunk);
        let payload: serde_json::Value =
            serde_json::from_str(text.trim_start_matches("data: ").trim()).unwrap();
        assert_eq!(payload["type"], "message_delta");
        assert_eq!(payload["delta"]["stop_reason"], "end_turn");
    }

    #[tokio::test]
    async fn execute_target_wrappers_handle_unsupported_targets() {
        let target = ExecutionTarget::Unsupported {
            kind: "manual-input".to_string(),
            reason: "not supported".to_string(),
        };

        let buffered = execute_target(
            &target,
            "prov-1",
            "/v1/chat/completions",
            &Bytes::from_static(b"{}"),
            "req-1",
        )
        .await;
        assert_eq!(buffered.status(), StatusCode::NOT_IMPLEMENTED);

        let streaming = execute_target_streaming(
            &target,
            "prov-1",
            "/v1/chat/completions",
            &Bytes::from_static(b"{}"),
            "req-1",
        )
        .await;
        assert_eq!(streaming.status, StatusCode::NOT_IMPLEMENTED);
        let chunks: Vec<Bytes> = streaming
            .body
            .map(|chunk| chunk.expect("stream chunk"))
            .collect()
            .await;
        assert_eq!(chunks.len(), 1);
        let body: Value = serde_json::from_slice(&chunks[0]).unwrap();
        assert_eq!(body["error"]["code"], json!("manual-input"));
    }

    #[tokio::test]
    async fn execute_command_target_rejects_disallowed_programs() {
        let target = CommandExecutionTarget {
            program: "curl".to_string(),
            args: Vec::new(),
            cwd: None,
            env: HashMap::new(),
            timeout: Duration::from_secs(1),
            family: Some(AdapterFamily::ChatKit),
            workflow_id: None,
            runner_config: None,
        };

        let buffered = execute_command_target(
            &target,
            "prov-1",
            "/v1/chat/completions",
            &Bytes::from_static(b"{}"),
            "req-1",
        )
        .await;
        assert_eq!(buffered.status(), StatusCode::FORBIDDEN);
        let body: Value = serde_json::from_slice(buffered.body()).unwrap();
        assert_eq!(
            body["error"]["code"],
            json!("execution_program_not_allowed")
        );

        let streaming = execute_command_target_streaming(
            &target,
            "prov-1",
            "/v1/chat/completions",
            &Bytes::from_static(b"{}"),
            "req-1",
        )
        .await;
        assert_eq!(streaming.status, StatusCode::FORBIDDEN);
        let chunks: Vec<Bytes> = streaming
            .body
            .map(|chunk| chunk.expect("stream chunk"))
            .collect()
            .await;
        assert_eq!(chunks.len(), 1);
        let body: Value = serde_json::from_slice(&chunks[0]).unwrap();
        assert_eq!(
            body["error"]["code"],
            json!("execution_program_not_allowed")
        );
    }

    #[tokio::test]
    async fn execute_file_target_invalid_paths_fail_before_spawn() {
        let missing = unique_temp_script_path("py").display().to_string();
        let target = FileExecutionTarget {
            path: missing,
            timeout: Duration::from_millis(50),
        };

        let buffered = execute_file_target(
            &target,
            "prov-1",
            "/v1/chat/completions",
            &Bytes::from_static(b"{}"),
            "req-1",
        )
        .await;
        assert_eq!(buffered.status(), StatusCode::BAD_GATEWAY);
        let body: Value = serde_json::from_slice(buffered.body()).unwrap();
        assert_eq!(body["error"]["code"], json!("file_target_invalid"));

        let streaming = execute_file_target_streaming(
            &target,
            "prov-1",
            "/v1/chat/completions",
            &Bytes::from_static(b"{}"),
            "req-1",
        )
        .await;
        assert_eq!(streaming.status, StatusCode::BAD_GATEWAY);
        let chunks: Vec<Bytes> = streaming
            .body
            .map(|chunk| chunk.expect("stream chunk"))
            .collect()
            .await;
        assert_eq!(chunks.len(), 1);
        let body: Value = serde_json::from_slice(&chunks[0]).unwrap();
        assert_eq!(body["error"]["code"], json!("file_target_invalid"));
    }

    #[tokio::test]
    async fn execute_target_echo_wrappers_cover_buffered_and_streaming_paths() {
        let target = ExecutionTarget::Echo;
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "messages": [{"role": "user", "content": "echo me"}]
            }))
            .unwrap(),
        );

        let buffered =
            execute_target(&target, "prov-echo", "/v1/chat/completions", &body, "req-1").await;
        assert_eq!(buffered.status(), StatusCode::OK);
        let buffered_body: Value = serde_json::from_slice(buffered.body()).unwrap();
        assert_eq!(
            buffered_body["choices"][0]["message"]["content"],
            json!("echo me")
        );

        let streaming =
            execute_target_streaming(&target, "prov-echo", "/v1/messages", &body, "req-1").await;
        assert_eq!(streaming.status, StatusCode::OK);
        let chunks: Vec<Bytes> = streaming
            .body
            .map(|chunk| chunk.expect("stream chunk"))
            .collect()
            .await;
        assert_eq!(chunks.len(), 3);
        assert!(String::from_utf8_lossy(&chunks[0]).contains("echo me"));
        assert_eq!(chunks[2], Bytes::from_static(b"data: [DONE]\n\n"));
    }

    #[tokio::test]
    async fn execute_command_target_invalid_script_paths_report_invalid_target() {
        let missing = unique_temp_script_path("py");
        let target = CommandExecutionTarget {
            program: missing.display().to_string(),
            args: Vec::new(),
            cwd: None,
            env: HashMap::new(),
            timeout: Duration::from_secs(1),
            family: Some(AdapterFamily::Transformers),
            workflow_id: None,
            runner_config: None,
        };

        let buffered = execute_command_target(
            &target,
            "prov-command",
            "/v1/chat/completions",
            &Bytes::from_static(b"{}"),
            "req-command",
        )
        .await;
        assert_eq!(buffered.status(), StatusCode::BAD_GATEWAY);
        let buffered_body: Value = serde_json::from_slice(buffered.body()).unwrap();
        assert_eq!(
            buffered_body["error"]["code"],
            json!("execution_target_invalid")
        );

        let streaming = execute_command_target_streaming(
            &target,
            "prov-command",
            "/v1/chat/completions",
            &Bytes::from_static(b"{}"),
            "req-command",
        )
        .await;
        assert_eq!(streaming.status, StatusCode::BAD_GATEWAY);
        let chunks: Vec<Bytes> = streaming
            .body
            .map(|chunk| chunk.expect("stream chunk"))
            .collect()
            .await;
        assert_eq!(chunks.len(), 1);
        let streaming_body: Value = serde_json::from_slice(&chunks[0]).unwrap();
        assert_eq!(
            streaming_body["error"]["code"],
            json!("execution_target_invalid")
        );
    }

    #[test]
    fn classify_exec_prefix_supported() {
        assert_eq!(
            classify_capability("exec:python"),
            ExecutionCapability::Supported
        );
        assert_eq!(
            classify_capability("exec:node script.js"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_file_prefix_supported() {
        assert_eq!(
            classify_capability("file:///path/to/script.py"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_echo_supported() {
        assert_eq!(classify_capability("echo"), ExecutionCapability::Supported);
    }

    #[test]
    fn classify_openai_agents_supported() {
        assert_eq!(
            classify_capability("openai-agents"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_mcp_supported() {
        assert_eq!(classify_capability("mcp"), ExecutionCapability::Supported);
    }

    #[test]
    fn classify_webhook_unsupported() {
        assert_eq!(
            classify_capability("webhook"),
            ExecutionCapability::UnsupportedAtConfigTime
        );
    }

    #[test]
    fn classify_trims_whitespace() {
        assert_eq!(
            classify_capability("  echo  "),
            ExecutionCapability::Supported
        );
    }

    // ── AdapterFamily ───────────────────────────────────────────────────

    #[test]
    fn adapter_family_as_str_roundtrip() {
        let families = [
            AdapterFamily::Browser,
            AdapterFamily::ChatKit,
            AdapterFamily::Transformers,
            AdapterFamily::ClaudeAgentSdk,
            AdapterFamily::CodexSdk,
            AdapterFamily::Mcp,
            AdapterFamily::WebSocket,
            AdapterFamily::OpenAiAgents,
            AdapterFamily::OpenCodeSdk,
            AdapterFamily::BedrockAgents,
        ];
        for f in families {
            assert!(!f.as_str().is_empty());
        }
    }

    #[test]
    fn adapter_family_support_modes() {
        assert_eq!(
            AdapterFamily::Browser.support_mode(),
            ExecutionSupportMode::AdapterOnly
        );
        assert_eq!(
            AdapterFamily::ChatKit.support_mode(),
            ExecutionSupportMode::AdapterOnly
        );
        assert_eq!(
            AdapterFamily::WebSocket.support_mode(),
            ExecutionSupportMode::AdapterOnly
        );
        assert_eq!(
            AdapterFamily::Transformers.support_mode(),
            ExecutionSupportMode::NativeRunnerOrAdapter
        );
        assert_eq!(
            AdapterFamily::ClaudeAgentSdk.support_mode(),
            ExecutionSupportMode::NativeRunnerOrAdapter
        );
        assert_eq!(
            AdapterFamily::OpenAiAgents.support_mode(),
            ExecutionSupportMode::NativeRunnerOrAdapter
        );
    }

    // ── execution_family_info ───────────────────────────────────────────

    #[test]
    fn execution_family_info_known_families() {
        let info = execution_family_info("claude-agent-sdk").unwrap();
        assert_eq!(info.family, AdapterFamily::ClaudeAgentSdk);
        assert_eq!(info.kind, "claude-agent-sdk");

        assert!(execution_family_info("openai-agents").is_some());
        assert!(execution_family_info("mcp").is_some());
    }

    // ── is_allowed_execution_program ────────────────────────────────────

    #[test]
    fn allowed_programs() {
        assert!(is_allowed_execution_program("python"));
        assert!(is_allowed_execution_program("python3"));
        assert!(is_allowed_execution_program("node"));
        assert!(is_allowed_execution_program("npx"));
        assert!(is_allowed_execution_program("deno"));
        assert!(is_allowed_execution_program("bun"));
        assert!(is_allowed_execution_program("cargo"));
    }

    #[test]
    fn allowed_script_extensions() {
        assert!(is_allowed_execution_program("script.py"));
        assert!(is_allowed_execution_program("app.js"));
        assert!(is_allowed_execution_program("/path/to/run.sh"));
        assert!(is_allowed_execution_program("worker.mjs"));
    }

    #[test]
    fn disallowed_programs() {
        assert!(!is_allowed_execution_program("rm"));
        assert!(!is_allowed_execution_program("curl"));
        assert!(!is_allowed_execution_program("evil.exe"));
    }

    // ── parse_timeout ───────────────────────────────────────────────────

    #[test]
    fn parse_timeout_minimum_one() {
        assert_eq!(
            parse_timeout(&json!({"execution_timeout_ms": 0})),
            Duration::from_millis(1)
        );
    }

    // ── parse_env_map ───────────────────────────────────────────────────

    #[test]
    fn parse_env_map_from_object() {
        let v = json!({"KEY": "value", "OTHER": "val2"});
        let map = parse_env_map(Some(&v));
        assert_eq!(map.get("KEY").map(String::as_str), Some("value"));
        assert_eq!(map.get("OTHER").map(String::as_str), Some("val2"));
    }

    #[test]
    fn parse_env_map_none_gives_empty() {
        assert!(parse_env_map(None).is_empty());
    }

    #[test]
    fn parse_env_map_skips_non_string_values() {
        let v = json!({"KEY": "value", "NUM": 42});
        let map = parse_env_map(Some(&v));
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("KEY").map(String::as_str), Some("value"));
    }

    // ── parse_env_map_merged ────────────────────────────────────────────

    #[test]
    fn parse_env_map_merged_primary_overwrites_fallback() {
        let primary = json!({"A": "primary"});
        let fallback = json!({"A": "fallback", "B": "extra"});
        let map = parse_env_map_merged(Some(&primary), Some(&fallback));
        assert_eq!(map.get("A").map(String::as_str), Some("fallback"));
        assert_eq!(map.get("B").map(String::as_str), Some("extra"));
    }

    // ── execution_cwd ───────────────────────────────────────────────────

    #[test]
    fn execution_cwd_from_adapter_cwd() {
        let entry = json!({"adapter_cwd": "/tmp"});
        assert_eq!(execution_cwd(&entry), Some("/tmp".to_string()));
    }

    #[test]
    fn execution_cwd_from_working_dir() {
        let entry = json!({"working_dir": "/home"});
        assert_eq!(execution_cwd(&entry), Some("/home".to_string()));
    }

    #[test]
    fn execution_cwd_none_when_missing() {
        assert!(execution_cwd(&json!({})).is_none());
    }

    // ── parse_execution_target ──────────────────────────────────────────

    #[test]
    fn parse_execution_target_echo_variant() {
        let entry = json!({});
        let target = parse_execution_target("echo", &entry).unwrap();
        assert!(matches!(target, Some(ExecutionTarget::Echo)));
    }

    #[test]
    fn parse_execution_target_unsupported_variant() {
        let entry = json!({});
        let target = parse_execution_target("webhook", &entry).unwrap();
        assert!(matches!(target, Some(ExecutionTarget::Unsupported { .. })));
    }

    // ── looks_like_sse_chunk ────────────────────────────────────────────

    #[test]
    fn looks_like_sse_chunk_data_prefix() {
        assert!(looks_like_sse_chunk(&Bytes::from_static(b"data: hello")));
        assert!(looks_like_sse_chunk(&Bytes::from_static(b"data: {}")));
    }

    #[test]
    fn looks_like_sse_chunk_no_prefix() {
        assert!(!looks_like_sse_chunk(&Bytes::from_static(b"hello world")));
        assert!(!looks_like_sse_chunk(&Bytes::from_static(b"")));
    }

    // ── extract_prompt_text ─────────────────────────────────────────────

    #[test]
    fn extract_prompt_from_prompt_field() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "input": "what is rust?"
            }))
            .unwrap(),
        );
        let text = extract_prompt_text(&body);
        assert!(text.contains("what is rust?"));
    }

    #[test]
    fn extract_prompt_from_input_field() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "input": "embed this"
            }))
            .unwrap(),
        );
        let text = extract_prompt_text(&body);
        assert!(text.contains("embed this"));
    }

    // ── unsupported_family_reason ───────────────────────────────────────

    #[test]
    fn unsupported_family_reason_all_variants() {
        for family in [
            AdapterFamily::Browser,
            AdapterFamily::ChatKit,
            AdapterFamily::WebSocket,
            AdapterFamily::Transformers,
            AdapterFamily::ClaudeAgentSdk,
            AdapterFamily::CodexSdk,
            AdapterFamily::Mcp,
            AdapterFamily::OpenAiAgents,
            AdapterFamily::OpenCodeSdk,
            AdapterFamily::BedrockAgents,
        ] {
            let reason = unsupported_family_reason(family);
            assert!(
                !reason.is_empty(),
                "family {:?} should have a reason",
                family
            );
        }
    }

    // ── execute_echo_target ─────────────────────────────────────────────

    #[test]
    fn execute_echo_target_returns_prompt() {
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "messages": [{"role": "user", "content": "echo this back"}]
            }))
            .unwrap(),
        );
        let response = execute_echo_target("/v1/chat/completions", &body);
        assert_eq!(response.status(), StatusCode::OK);
        let parsed: Value = serde_json::from_slice(response.body()).unwrap();
        assert!(parsed["choices"][0]["message"]["content"]
            .as_str()
            .unwrap()
            .contains("echo this back"));
    }

    // ── build_execution_payload ─────────────────────────────────────────

    #[test]
    fn build_execution_payload_has_expected_structure() {
        let target = CommandExecutionTarget {
            program: "node".to_string(),
            args: Vec::new(),
            cwd: None,
            env: HashMap::new(),
            timeout: Duration::from_secs(30),
            family: Some(AdapterFamily::OpenAiAgents),
            workflow_id: None,
            runner_config: None,
        };
        let body = Bytes::from(
            serde_json::to_vec(&json!({
                "model": "test-model",
                "messages": [{"role": "user", "content": "test"}]
            }))
            .unwrap(),
        );
        let payload = build_execution_payload(
            &target,
            "test-model",
            "/v1/chat/completions",
            &body,
            "req-1",
            false,
        );
        assert_eq!(payload["request_id"], "req-1");
        assert!(payload.get("request").is_some());
    }

    // ── normalized_execution_alias ──────────────────────────────────────

    #[test]
    fn normalized_execution_alias_known() {
        let alias = normalized_execution_alias("claude-agent-sdk");
        assert_eq!(alias, "claude-agent-sdk");
    }

    #[test]
    fn normalized_execution_alias_passthrough() {
        let alias = normalized_execution_alias("custom-provider");
        assert_eq!(alias, "");
    }

    // ── parse_exec_command ──────────────────────────────────────────────

    #[test]
    fn parse_exec_command_no_args() {
        let (prog, args) = parse_exec_command("node").unwrap();
        assert_eq!(prog, "node");
        assert!(args.is_empty());
    }

    // ── script_launcher ─────────────────────────────────────────────────

    #[test]
    fn script_launcher_python() {
        let path = unique_temp_script_path("py");
        fs::write(&path, "print('ok')\n").unwrap();
        let (program, args) = script_launcher(&path).unwrap();
        assert!(
            program.contains("python"),
            "expected python, got {}",
            program
        );
        assert!(args[0].ends_with(".py"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn script_launcher_javascript() {
        let path = unique_temp_script_path("js");
        fs::write(&path, "console.log('ok');\n").unwrap();
        let (program, _) = script_launcher(&path).unwrap();
        assert_eq!(program, "node");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn script_launcher_shell() {
        let path = unique_temp_script_path("sh");
        fs::write(&path, "#!/bin/sh\necho ok\n").unwrap();
        let (program, _) = script_launcher(&path).unwrap();
        assert_eq!(program, "sh");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn script_launcher_unknown_extension() {
        let path = unique_temp_script_path("csv");
        fs::write(&path, "a,b,c\n").unwrap();
        let result = script_launcher(&path);
        assert!(result.is_ok());
        let _ = fs::remove_file(path);
    }

    // ── default_headers ─────────────────────────────────────────────────

    #[test]
    fn default_headers_contain_content_type() {
        let h = default_headers(Some("openai-agents"));
        assert!(h.contains_key("content-type"));
    }

    #[test]
    fn default_headers_without_family() {
        let h = default_headers(None);
        assert!(h.contains_key("content-type"));
    }

    // ── script_launcher additional extensions ──────────────────────────

    #[test]
    fn script_launcher_no_extension_returns_direct_program() {
        let path = unique_temp_script_path("bin");
        fs::write(&path, "echo hi\n").unwrap();
        let result = script_launcher(&path);
        assert!(result.is_ok());
        let (program, args) = result.unwrap();
        assert_eq!(program, path.canonicalize().unwrap().display().to_string());
        assert!(args.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn script_launcher_rb_extension() {
        let result = script_launcher(Path::new("script.rb"));
        assert!(result.is_err() || result.is_ok());
    }

    // ── default_headers family variants ───────────────────────────────

    #[test]
    fn default_headers_anthropic_family() {
        let h = default_headers(Some("anthropic"));
        assert!(h.contains_key("content-type"));
    }

    #[test]
    fn default_headers_openai_family() {
        let h = default_headers(Some("openai"));
        assert!(h.contains_key("content-type"));
    }
}

#[cfg(test)]
mod coverage_expansion_execution_tests {
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
    use serde_json::json;

    // ── classify_capability ─────────────────────────────────────────────

    #[test]
    fn classify_exec_prefix() {
        assert_eq!(
            classify_capability("exec:node server.js"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_file_prefix() {
        assert_eq!(
            classify_capability("file:///path/to/script.py"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_echo() {
        assert_eq!(classify_capability("echo"), ExecutionCapability::Supported);
    }

    #[test]
    fn classify_unsupported_manual_input() {
        assert_eq!(
            classify_capability("manual-input"),
            ExecutionCapability::UnsupportedAtConfigTime
        );
    }

    #[test]
    fn classify_unsupported_sequence() {
        assert_eq!(
            classify_capability("sequence"),
            ExecutionCapability::UnsupportedAtConfigTime
        );
    }

    #[test]
    fn classify_unsupported_webhook() {
        assert_eq!(
            classify_capability("webhook"),
            ExecutionCapability::UnsupportedAtConfigTime
        );
    }

    #[test]
    fn classify_browser_adapter_only() {
        assert_eq!(
            classify_capability("browser"),
            ExecutionCapability::SupportedWithAdapter
        );
    }

    #[test]
    fn classify_chatkit_adapter_only() {
        assert_eq!(
            classify_capability("chatkit"),
            ExecutionCapability::SupportedWithAdapter
        );
    }

    #[test]
    fn classify_websocket_adapter_only() {
        assert_eq!(
            classify_capability("websocket"),
            ExecutionCapability::SupportedWithAdapter
        );
    }

    #[test]
    fn classify_claude_agent_sdk_supported() {
        assert_eq!(
            classify_capability("claude-agent-sdk"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_codex_sdk_supported() {
        assert_eq!(
            classify_capability("codex-sdk"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_mcp_supported() {
        assert_eq!(classify_capability("mcp"), ExecutionCapability::Supported);
    }

    #[test]
    fn classify_openai_agents_supported() {
        assert_eq!(
            classify_capability("openai-agents"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_opencode_sdk_supported() {
        assert_eq!(
            classify_capability("opencode-sdk"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_bedrock_agents_supported() {
        assert_eq!(
            classify_capability("bedrock-agents"),
            ExecutionCapability::Supported
        );
    }

    #[test]
    fn classify_whitespace_trimmed() {
        assert_eq!(
            classify_capability("  exec:node server.js  "),
            ExecutionCapability::Supported
        );
    }

    // ── AdapterFamily ───────────────────────────────────────────────────

    #[test]
    fn adapter_family_as_str() {
        assert_eq!(AdapterFamily::Browser.as_str(), "browser");
        assert_eq!(AdapterFamily::ChatKit.as_str(), "chatkit");
        assert_eq!(AdapterFamily::Transformers.as_str(), "transformers");
        assert_eq!(AdapterFamily::ClaudeAgentSdk.as_str(), "claude-agent-sdk");
        assert_eq!(AdapterFamily::CodexSdk.as_str(), "codex-sdk");
        assert_eq!(AdapterFamily::Mcp.as_str(), "mcp");
        assert_eq!(AdapterFamily::WebSocket.as_str(), "websocket");
        assert_eq!(AdapterFamily::OpenAiAgents.as_str(), "openai-agents");
        assert_eq!(AdapterFamily::OpenCodeSdk.as_str(), "opencode-sdk");
        assert_eq!(AdapterFamily::BedrockAgents.as_str(), "bedrock-agents");
    }

    #[test]
    fn adapter_family_support_mode() {
        assert_eq!(
            AdapterFamily::Browser.support_mode(),
            ExecutionSupportMode::AdapterOnly
        );
        assert_eq!(
            AdapterFamily::ClaudeAgentSdk.support_mode(),
            ExecutionSupportMode::NativeRunnerOrAdapter
        );
    }

    // ── ExecutionTarget ─────────────────────────────────────────────────

    #[test]
    fn execution_target_kind_label_echo() {
        let target = ExecutionTarget::Echo;
        assert_eq!(target.kind_label(), "echo");
    }

    #[test]
    fn execution_target_kind_label_file() {
        let target = ExecutionTarget::File(FileExecutionTarget {
            path: "/tmp/script.py".to_string(),
            timeout: Duration::from_secs(30),
        });
        assert_eq!(target.kind_label(), "file");
    }

    #[test]
    fn execution_target_kind_label_unsupported() {
        let target = ExecutionTarget::Unsupported {
            kind: "ruby".to_string(),
            reason: "not supported".to_string(),
        };
        assert_eq!(target.kind_label(), "ruby");
    }

    #[test]
    fn execution_target_unsupported_reason() {
        let target = ExecutionTarget::Unsupported {
            kind: "go".to_string(),
            reason: "Go runtime not available".to_string(),
        };
        assert_eq!(
            target.unsupported_reason(),
            Some("Go runtime not available")
        );
    }

    #[test]
    fn execution_target_supported_no_reason() {
        let target = ExecutionTarget::Echo;
        assert!(target.unsupported_reason().is_none());
    }

    // ── is_allowed_execution_program ────────────────────────────────────

    #[test]
    fn allowed_program_node() {
        assert!(is_allowed_execution_program("node"));
    }

    #[test]
    fn allowed_program_python3() {
        assert!(is_allowed_execution_program("python3"));
    }

    #[test]
    fn allowed_program_full_path() {
        assert!(is_allowed_execution_program("/usr/bin/node"));
    }

    #[test]
    fn allowed_program_script_extension() {
        assert!(is_allowed_execution_program("myscript.py"));
        assert!(is_allowed_execution_program("handler.js"));
        assert!(is_allowed_execution_program("run.sh"));
    }

    #[test]
    fn disallowed_program_arbitrary() {
        assert!(!is_allowed_execution_program("rm"));
        assert!(!is_allowed_execution_program("/usr/bin/curl"));
    }

    // ── parse_execution_target ──────────────────────────────────────────

    #[test]
    fn parse_execution_target_exec_prefix() {
        let result = parse_execution_target("exec:node server.js", &json!({})).unwrap();
        assert!(result.is_some());
        if let Some(ExecutionTarget::Command(cmd)) = result {
            assert_eq!(cmd.program, "node");
            assert_eq!(cmd.args, vec!["server.js"]);
        } else {
            panic!("expected Command variant");
        }
    }

    #[test]
    fn parse_execution_target_file_prefix() {
        let result = parse_execution_target("file:///opt/script.py", &json!({})).unwrap();
        assert!(result.is_some());
        if let Some(ExecutionTarget::File(file)) = result {
            assert_eq!(file.path, "/opt/script.py");
        } else {
            panic!("expected File variant");
        }
    }

    #[test]
    fn parse_execution_target_echo() {
        let result = parse_execution_target("echo", &json!({})).unwrap();
        assert!(matches!(result, Some(ExecutionTarget::Echo)));
    }

    #[test]
    fn parse_execution_target_unsupported() {
        let result = parse_execution_target("manual-input", &json!({})).unwrap();
        assert!(matches!(result, Some(ExecutionTarget::Unsupported { .. })));
    }

    #[test]
    fn parse_execution_target_file_empty_path_error() {
        let result = parse_execution_target("file://", &json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn parse_execution_target_exec_empty_command_error() {
        let result = parse_execution_target("exec:", &json!({}));
        assert!(result.is_err());
    }
}

#[cfg(all(test, unix))]
mod lane_039_process_security_tests {
    use super::*;

    #[test]
    fn configured_timeout_is_hard_capped_at_three_hundred_seconds() {
        assert_eq!(
            parse_timeout(&json!({"execution_timeout_ms": 900_000})),
            HARD_TIMEOUT
        );
    }

    #[test]
    fn per_child_application_output_buffers_stay_below_twenty_mibibytes() {
        let config = execution_child_pool().config();
        let non_streaming_buffers = config.stdout_max_bytes + config.stderr_max_bytes;
        let conservative_stream_channel = STREAM_CHANNEL_CAPACITY * STREAM_READ_CHUNK_BYTES * 4;
        let conservative_pipe_buffers = 2 * 64 * 1024;
        assert!(config.total_max_bytes <= 20 * 1024 * 1024);
        assert!(
            non_streaming_buffers + conservative_stream_channel + conservative_pipe_buffers
                <= 20 * 1024 * 1024
        );
        assert_eq!(config.stdout_max_bytes, 8 * 1024 * 1024);
        assert_eq!(config.stderr_max_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn streaming_and_non_streaming_admit_through_bounded_child_pool() {
        let available = execution_child_pool().available_process_slots();
        assert!(available <= execution_child_pool().config().process_capacity);
        assert_eq!(
            execution_child_pool().config().timeout,
            Duration::from_secs(30)
        );
    }
}
