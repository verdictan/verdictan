// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use crate::error::CliError;
use crate::persistence::{atomic_write, atomic_write_private, PrivateFileMode};

/// Default system account for a system-scope Linux install.
pub const SYSTEM_SERVICE_USER: &str = "verdictan";

/// Directory that holds system-scope configuration and the protected
/// environment file. `gateway run` reads `policy-config.yaml` from here.
pub const SYSTEM_CONFIG_DIR: &str = "/etc/verdictan";

const SYSTEMD_SYSTEM_UNIT_DIR: &str = "/etc/systemd/system";
const LAUNCH_DAEMON_DIR: &str = "/Library/LaunchDaemons";
const SYSTEM_LOG_DIR: &str = "/var/log/verdictan";

/// Registry root that holds a Windows service registration. The install has no
/// unit file on Windows, so this key stands in for one in operator output.
const WINDOWS_SERVICE_REGISTRY_ROOT: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";

/// Whether a service runs for one login session or for the whole host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceScope {
    /// Registered for the invoking user, and stopped when that user logs out
    /// unless linger is enabled.
    User,
    /// Registered for the host, and started at boot without a login.
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServicePlatform {
    /// macOS LaunchAgent in the invoking user's domain.
    Launchd,
    /// macOS LaunchDaemon in the system domain.
    LaunchDaemon,
    SystemdUser,
    /// systemd unit in `/etc/systemd/system`.
    SystemdSystem,
    /// Windows Service registered through `sc.exe`.
    WindowsService,
}

impl ServicePlatform {
    pub fn scope(&self) -> ServiceScope {
        match self {
            Self::Launchd | Self::SystemdUser => ServiceScope::User,
            Self::LaunchDaemon | Self::SystemdSystem | Self::WindowsService => ServiceScope::System,
        }
    }

    /// Operator-facing name of the service manager and its scope.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Launchd => "launchd",
            Self::LaunchDaemon => "launchd (system)",
            Self::SystemdUser => "systemd --user",
            Self::SystemdSystem => "systemd (system)",
            Self::WindowsService => "windows service",
        }
    }

    fn is_systemd(&self) -> bool {
        matches!(self, Self::SystemdUser | Self::SystemdSystem)
    }
}

/// Substrings that mark an environment variable as secret material.
///
/// The match is deliberately wide. A false positive only narrows a file mode,
/// and a false negative leaves a live credential world readable.
const SECRET_ENV_KEY_FRAGMENTS: &[&str] =
    &["TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL", "COOKIE"];

fn is_secret_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    SECRET_ENV_KEY_FRAGMENTS
        .iter()
        .any(|fragment| upper.contains(fragment))
}

/// Reports whether a rendered service file would embed secret material.
fn env_carries_secret_material(env: &BTreeMap<String, String>) -> bool {
    env.iter()
        .any(|(key, value)| is_secret_env_key(key) && !value.trim().is_empty())
}

/// Writes a file that embeds secret material with owner-only permissions.
///
/// A target without Unix file modes gives no restriction. That outcome is
/// reported to the operator on stderr and through `tracing`, because the file
/// then keeps the permissions of its parent directory.
fn write_secret_bearing_file(path: &Path, contents: &str) -> Result<(), CliError> {
    let protection = atomic_write_private(path, contents.as_bytes()).map_err(|e| {
        CliError::user(format!(
            "failed to write protected file {}: {e}",
            path.display()
        ))
    })?;

    if protection == PrivateFileMode::Unsupported {
        report_unrestricted_secret_file(path);
    }
    Ok(())
}

fn report_unrestricted_secret_file(path: &Path) {
    let target = std::env::consts::OS;
    tracing::warn!(
        path = %path.display(),
        target_os = target,
        "wrote a file that holds credentials without an owner-only file mode"
    );
    eprintln!(
        "warning: {} holds service credentials and could not receive an owner-only \
         file mode on {target}. Restrict access to this file before you leave the host.",
        path.display()
    );
}

#[derive(Debug, Clone)]
pub struct GatewayServiceInstallSpec {
    pub name: String,
    pub listen: String,
    pub upstream: Option<String>,
    pub policy_configs: Vec<PathBuf>,
    pub fail_mode: String,
    pub max_concurrency: Option<usize>,
    pub connected_mode: bool,
    pub api_token: Option<String>,
    pub agent_id: Option<String>,
    pub env: BTreeMap<String, String>,
    pub command_override: Option<Vec<String>>,
    pub binary_path_override: Option<PathBuf>,
}

fn merged_service_env(spec: &GatewayServiceInstallSpec) -> BTreeMap<String, String> {
    let mut env = spec.env.clone();
    if let Some(agent_id) = &spec.agent_id {
        if !agent_id.trim().is_empty() {
            env.insert("VERDICTAN_AGENT_ID".to_string(), agent_id.clone());
        }
    }
    if let Some(api_token) = &spec.api_token {
        if !api_token.trim().is_empty() {
            env.insert("VERDICTAN_API_TOKEN".to_string(), api_token.clone());
        }
    }
    env
}

fn contains_control_characters(value: &str) -> bool {
    value.chars().any(|ch| {
        let code = ch as u32;
        (0x01..=0x1f).contains(&code) || code == 0x7f
    })
}

fn validate_launchd_env_value(name: &str, value: &str) -> Result<(), CliError> {
    if contains_control_characters(value) {
        return Err(CliError::user(format!(
            "{name} contains unsupported control characters for launchd service installation"
        )));
    }
    Ok(())
}

fn validate_launchd_environment_map(env: &BTreeMap<String, String>) -> Result<(), CliError> {
    for (key, value) in env {
        validate_launchd_env_value(key, value)?;
    }
    Ok(())
}

fn service_binary_path(spec: &GatewayServiceInstallSpec) -> Result<String, CliError> {
    if let Some(path) = &spec.binary_path_override {
        return canonicalize_lossy(path);
    }
    let exe = std::env::current_exe()
        .map_err(|e| CliError::internal(format!("failed to resolve current executable: {e}")))?;
    canonicalize_lossy(&exe)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub platform: ServicePlatform,
    pub label: String,
    pub state: String,
    pub pid: Option<u32>,
    pub service_file: PathBuf,
}

/// One file that an install must write.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceFileWrite {
    path: PathBuf,
    contents: String,
    /// True when the contents embed credentials, so the file needs an
    /// owner-only mode.
    private: bool,
}

/// Everything an install writes or creates, resolved before any side effect.
///
/// The plan is pure, so unit tests can assert path resolution, unit content,
/// and file modes without a privileged operation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceInstallPlan {
    /// Directories to create, in order, before the writes.
    directories: Vec<PathBuf>,
    files: Vec<ServiceFileWrite>,
    /// System account that a system-scope Linux unit runs as.
    service_user: Option<String>,
    /// Unit file that identifies the installed service.
    service_file: PathBuf,
}

fn build_install_plan(
    platform: &ServicePlatform,
    spec: &GatewayServiceInstallSpec,
) -> Result<ServiceInstallPlan, CliError> {
    let safe_name = require_safe_service_name(&spec.name)?;
    let service_file = service_file_path(platform, &spec.name)?;
    let env = merged_service_env(spec);
    let has_secret = env_carries_secret_material(&env);

    let mut directories = Vec::new();
    if let Some(parent) = service_file.parent() {
        directories.push(parent.to_path_buf());
    }
    if platform.scope() == ServiceScope::System {
        directories.push(PathBuf::from(SYSTEM_CONFIG_DIR));
    }
    if matches!(
        platform,
        ServicePlatform::Launchd | ServicePlatform::LaunchDaemon
    ) {
        directories.push(logs_dir(platform)?);
    }

    let mut files = Vec::new();
    let environment_file = if platform.is_systemd() && !env.is_empty() {
        Some(environment_file_path(platform, &safe_name)?)
    } else {
        None
    };

    if let Some(path) = &environment_file {
        if let Some(parent) = path.parent() {
            directories.push(parent.to_path_buf());
        }
        files.push(ServiceFileWrite {
            path: path.clone(),
            contents: render_systemd_environment_file(&env)?,
            private: true,
        });
    }

    let contents = match platform {
        ServicePlatform::Launchd | ServicePlatform::LaunchDaemon => {
            render_launchd_plist(spec, platform)?
        }
        ServicePlatform::SystemdUser | ServicePlatform::SystemdSystem => {
            render_systemd_unit(spec, platform, environment_file.as_deref())?
        }
        ServicePlatform::WindowsService => {
            return Err(CliError::internal(
                "windows service installation does not use a unit file",
            ))
        }
    };

    // A systemd unit that references an environment file embeds no secret. A
    // launchd plist has no environment-file mechanism, so it keeps the values
    // inline and needs the restricted mode itself.
    let unit_embeds_secret = has_secret && environment_file.is_none();
    files.push(ServiceFileWrite {
        path: service_file.clone(),
        contents,
        private: unit_embeds_secret,
    });

    let service_user = match platform {
        ServicePlatform::SystemdSystem => Some(SYSTEM_SERVICE_USER.to_string()),
        _ => None,
    };

    directories.dedup();
    Ok(ServiceInstallPlan {
        directories,
        files,
        service_user,
        service_file,
    })
}

pub fn install_service(
    spec: &GatewayServiceInstallSpec,
) -> Result<(ServicePlatform, PathBuf), CliError> {
    let platform = current_platform()?;
    if matches!(platform, ServicePlatform::WindowsService) {
        let registry_key = install_windows_service(spec)?;
        verify_service_is_active(&platform, &spec.name)?;
        return Ok((platform, registry_key));
    }

    let plan = build_install_plan(&platform, spec)?;
    if let Some(user) = &plan.service_user {
        ensure_system_service_user(user)?;
    }
    for directory in &plan.directories {
        std::fs::create_dir_all(directory).map_err(|e| {
            CliError::user(format!(
                "failed to create service directory {}: {e}",
                directory.display()
            ))
        })?;
    }
    for file in &plan.files {
        write_service_file(file)?;
    }

    activate_service(&platform, &spec.name, &plan.service_file)?;
    verify_service_is_active(&platform, &spec.name)?;
    Ok((platform, plan.service_file))
}

fn write_service_file(file: &ServiceFileWrite) -> Result<(), CliError> {
    if file.private {
        return write_secret_bearing_file(&file.path, &file.contents);
    }
    atomic_write(&file.path, file.contents.as_bytes()).map_err(|e| {
        CliError::user(format!(
            "failed to write service file {}: {e}",
            file.path.display()
        ))
    })
}

pub fn uninstall_service(name: &str) -> Result<(ServicePlatform, PathBuf), CliError> {
    let platform = installed_platform(name)?;
    let service_file = service_file_path(&platform, name)?;
    deactivate_service(&platform, name, &service_file)?;

    if matches!(platform, ServicePlatform::WindowsService) {
        run_command(
            "sc.exe",
            &["delete", &require_safe_service_name(name)?],
            true,
        )?;
        return Ok((platform, service_file));
    }

    if service_file.exists() {
        std::fs::remove_file(&service_file).map_err(|e| {
            CliError::user(format!(
                "failed to remove service file {}: {e}",
                service_file.display()
            ))
        })?;
    }

    // The environment file holds a live credential, so it must not outlive the
    // unit that referenced it.
    if platform.is_systemd() {
        let environment_file = environment_file_path(&platform, &require_safe_service_name(name)?)?;
        if environment_file.exists() {
            std::fs::remove_file(&environment_file).map_err(|e| {
                CliError::user(format!(
                    "failed to remove environment file {}: {e}",
                    environment_file.display()
                ))
            })?;
        }
        let reload = systemctl_args(&platform, &["daemon-reload"]);
        let reload = reload.iter().map(String::as_str).collect::<Vec<&str>>();
        run_command("systemctl", &reload, false)?;
    }

    Ok((platform, service_file))
}

pub fn service_status(name: &str) -> Result<ServiceStatus, CliError> {
    let platform = installed_platform(name)?;
    let service_file = service_file_path(&platform, name)?;
    let label = service_label(name);
    match platform {
        ServicePlatform::Launchd | ServicePlatform::LaunchDaemon => {
            launchctl_status(&platform, &label, service_file)
        }
        ServicePlatform::SystemdUser | ServicePlatform::SystemdSystem => {
            systemd_status(&platform, name, service_file)
        }
        ServicePlatform::WindowsService => windows_service_status(name, service_file),
    }
}

pub fn start_service(name: &str) -> Result<(ServicePlatform, PathBuf), CliError> {
    let platform = installed_platform(name)?;
    let service_file = service_file_path(&platform, name)?;
    if !service_registration_exists(&platform, name)? {
        return Err(CliError::user(format!("service {} is not installed", name)));
    }
    activate_service(&platform, name, &service_file)?;
    Ok((platform, service_file))
}

pub fn stop_service(name: &str) -> Result<(ServicePlatform, PathBuf), CliError> {
    let platform = installed_platform(name)?;
    let service_file = service_file_path(&platform, name)?;
    if !service_registration_exists(&platform, name)? {
        return Err(CliError::user(format!("service {} is not installed", name)));
    }
    deactivate_service(&platform, name, &service_file)?;
    Ok((platform, service_file))
}

pub fn service_file_exists(name: &str) -> Result<bool, CliError> {
    let platform = installed_platform(name)?;
    service_registration_exists(&platform, name)
}

fn service_registration_exists(platform: &ServicePlatform, name: &str) -> Result<bool, CliError> {
    if matches!(platform, ServicePlatform::WindowsService) {
        return windows_service_is_registered(name);
    }
    Ok(service_file_path(platform, name)?.exists())
}

/// Platforms that this operating system can manage, ordered by the scope that
/// the current process is entitled to.
fn candidate_platforms(os: &str, privileged: bool) -> Vec<ServicePlatform> {
    match (os, privileged) {
        ("macos", true) => vec![ServicePlatform::LaunchDaemon, ServicePlatform::Launchd],
        ("macos", false) => vec![ServicePlatform::Launchd],
        ("linux", true) => vec![ServicePlatform::SystemdSystem, ServicePlatform::SystemdUser],
        ("linux", false) => vec![ServicePlatform::SystemdUser],
        ("windows", _) => vec![ServicePlatform::WindowsService],
        _ => Vec::new(),
    }
}

fn resolve_platform(os: &str, privileged: bool) -> Result<ServicePlatform, CliError> {
    candidate_platforms(os, privileged)
        .into_iter()
        .next()
        .ok_or_else(|| {
            CliError::user(format!(
                "hosted gateway service management is not supported on {os}"
            ))
        })
}

/// Selects the scope that a new install targets.
///
/// A privileged process installs a host-wide service. An unprivileged process
/// keeps the user-scope service that the command has always registered.
pub(crate) fn current_platform() -> Result<ServicePlatform, CliError> {
    #[cfg(any(test, verdictan_cli_e2e))]
    if let Some(result) = test_service_platform_override() {
        return result;
    }

    resolve_platform(std::env::consts::OS, process_is_privileged())
}

/// Selects the scope that already holds an installed service, so that a
/// privileged `status`, `start`, `stop`, or `uninstall` still finds a
/// user-scope install and the reverse.
fn installed_platform(name: &str) -> Result<ServicePlatform, CliError> {
    #[cfg(any(test, verdictan_cli_e2e))]
    if let Some(result) = test_service_platform_override() {
        return result;
    }

    let candidates = candidate_platforms(std::env::consts::OS, process_is_privileged());
    for candidate in &candidates {
        if service_registration_exists(candidate, name)? {
            return Ok(candidate.clone());
        }
    }
    resolve_platform(std::env::consts::OS, process_is_privileged())
}

#[cfg(unix)]
fn process_is_privileged() -> bool {
    // `geteuid` takes no argument, cannot fail, and has no side effect. It is
    // the only way to read the effective user without a subprocess.
    #[allow(unsafe_code)]
    let effective_uid = unsafe { libc::geteuid() };
    effective_uid == 0
}

#[cfg(not(unix))]
fn process_is_privileged() -> bool {
    // Windows has no effective-user identifier to read here. A Windows service
    // install always needs an elevated shell, and `sc.exe` reports the access
    // failure, so no separate probe is used.
    false
}

/// Test seam for platform selection. The override is compiled only into the
/// crate's own test harness, so a shipped binary cannot redirect the scope.
#[cfg(any(test, verdictan_cli_e2e))]
fn test_service_platform_override() -> Option<Result<ServicePlatform, CliError>> {
    let value = std::env::var("VERDICTAN_TEST_SERVICE_PLATFORM").ok()?;
    Some(match value.as_str() {
        "launchd" => Ok(ServicePlatform::Launchd),
        "launch-daemon" => Ok(ServicePlatform::LaunchDaemon),
        "systemd-user" => Ok(ServicePlatform::SystemdUser),
        "systemd-system" => Ok(ServicePlatform::SystemdSystem),
        "windows-service" => Ok(ServicePlatform::WindowsService),
        other => Err(CliError::user(format!(
            "unsupported test service platform override: {other}"
        ))),
    })
}

fn service_label(name: &str) -> String {
    let suffix = sanitize_service_name(name);
    format!("com.verdictan.gateway.{suffix}")
}

pub fn sanitize_service_name(name: &str) -> String {
    let trimmed = name.trim();
    let cleaned: String = trimmed
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect();
    cleaned.trim_matches('-').to_string()
}

fn home_dir() -> Result<PathBuf, CliError> {
    // Test seam. The override is compiled only into the crate's own test
    // harness, so a shipped binary cannot redirect a service file write.
    #[cfg(any(test, verdictan_cli_e2e))]
    if let Some(path) = std::env::var_os("VERDICTAN_TEST_HOME") {
        return Ok(PathBuf::from(path));
    }

    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::user("HOME is not set"))
}

fn logs_dir(platform: &ServicePlatform) -> Result<PathBuf, CliError> {
    match platform {
        // A LaunchDaemon runs as root and must not write into a login home.
        ServicePlatform::LaunchDaemon => Ok(PathBuf::from(SYSTEM_LOG_DIR)),
        _ => Ok(home_dir()?.join(".verdictan/logs")),
    }
}

fn require_safe_service_name(name: &str) -> Result<String, CliError> {
    let safe_name = sanitize_service_name(name);
    if safe_name.is_empty() {
        return Err(CliError::user(
            "service name must contain at least one valid character",
        ));
    }
    Ok(safe_name)
}

fn service_file_path(platform: &ServicePlatform, name: &str) -> Result<PathBuf, CliError> {
    let safe_name = require_safe_service_name(name)?;

    Ok(match platform {
        ServicePlatform::Launchd => home_dir()?
            .join("Library/LaunchAgents")
            .join(format!("{}.plist", service_label(&safe_name))),
        ServicePlatform::LaunchDaemon => {
            PathBuf::from(LAUNCH_DAEMON_DIR).join(format!("{}.plist", service_label(&safe_name)))
        }
        ServicePlatform::SystemdUser => home_dir()?
            .join(".config/systemd/user")
            .join(format!("{safe_name}.service")),
        ServicePlatform::SystemdSystem => {
            PathBuf::from(SYSTEMD_SYSTEM_UNIT_DIR).join(format!("{safe_name}.service"))
        }
        // Windows keeps the registration in the registry, so the key stands in
        // for a unit file in operator output.
        ServicePlatform::WindowsService => {
            PathBuf::from(WINDOWS_SERVICE_REGISTRY_ROOT).join(&safe_name)
        }
    })
}

/// Path of the protected `EnvironmentFile=` that holds the service
/// environment, including a live `VERDICTAN_API_TOKEN`.
fn environment_file_path(platform: &ServicePlatform, safe_name: &str) -> Result<PathBuf, CliError> {
    match platform {
        ServicePlatform::SystemdSystem => {
            Ok(PathBuf::from(SYSTEM_CONFIG_DIR).join(format!("{safe_name}.env")))
        }
        ServicePlatform::SystemdUser => Ok(home_dir()?
            .join(".config/verdictan")
            .join(format!("{safe_name}.env"))),
        other => Err(CliError::internal(format!(
            "{} has no environment file",
            other.display_name()
        ))),
    }
}

/// Renders a systemd `EnvironmentFile=` body.
///
/// A control character in a value would inject an extra assignment, so the
/// render refuses one instead of escaping it.
fn render_systemd_environment_file(env: &BTreeMap<String, String>) -> Result<String, CliError> {
    let mut body = String::new();
    for (key, value) in env {
        validate_systemd_env_value(key, value)?;
        body.push_str(&format!("{key}=\"{}\"\n", systemd_escape(value)));
    }
    Ok(body)
}

fn validate_systemd_env_value(name: &str, value: &str) -> Result<(), CliError> {
    if contains_control_characters(value) {
        return Err(CliError::user(format!(
            "{name} contains unsupported control characters for systemd service installation"
        )));
    }
    Ok(())
}

pub fn render_launchd_plist(
    spec: &GatewayServiceInstallSpec,
    platform: &ServicePlatform,
) -> Result<String, CliError> {
    let exe = service_binary_path(spec)?;
    let working_dir = service_working_directory(platform)?;
    let args = command_args(spec)?;
    let logs_dir = logs_dir(platform)?;
    let stdout_path = logs_dir.join(format!("{}.out.log", sanitize_service_name(&spec.name)));
    let stderr_path = logs_dir.join(format!("{}.err.log", sanitize_service_name(&spec.name)));

    let mut plist = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n",
    );
    plist.push_str(&format!(
        "  <key>Label</key>\n  <string>{}</string>\n",
        xml_escape(&service_label(&spec.name))
    ));
    plist.push_str("  <key>ProgramArguments</key>\n  <array>\n");
    plist.push_str(&format!("    <string>{}</string>\n", xml_escape(&exe)));
    for arg in args {
        plist.push_str(&format!("    <string>{}</string>\n", xml_escape(&arg)));
    }
    plist.push_str("  </array>\n");
    plist.push_str(&format!(
        "  <key>WorkingDirectory</key>\n  <string>{}</string>\n",
        xml_escape(&working_dir.display().to_string())
    ));
    plist.push_str("  <key>KeepAlive</key>\n  <true/>\n");
    plist.push_str("  <key>RunAtLoad</key>\n  <true/>\n");
    plist.push_str(&format!(
        "  <key>StandardOutPath</key>\n  <string>{}</string>\n",
        xml_escape(&stdout_path.display().to_string())
    ));
    plist.push_str(&format!(
        "  <key>StandardErrorPath</key>\n  <string>{}</string>\n",
        xml_escape(&stderr_path.display().to_string())
    ));
    let env = merged_service_env(spec);
    validate_launchd_environment_map(&env)?;
    if !env.is_empty() {
        plist.push_str("  <key>EnvironmentVariables</key>\n  <dict>\n");
        for (key, value) in &env {
            plist.push_str(&format!(
                "    <key>{}</key>\n    <string>{}</string>\n",
                xml_escape(key),
                xml_escape(value)
            ));
        }
        plist.push_str("  </dict>\n");
    }
    plist.push_str("</dict>\n</plist>\n");
    Ok(plist)
}

/// Working directory of the service process.
///
/// A user-scope service keeps the directory that the operator installed from.
/// A system-scope service uses the root directory, because `ProtectHome` and
/// `ProtectSystem` deny a login directory and because the installer's working
/// directory must not become part of a host-wide unit.
fn service_working_directory(platform: &ServicePlatform) -> Result<PathBuf, CliError> {
    if platform.scope() == ServiceScope::System {
        return Ok(PathBuf::from("/"));
    }
    std::env::current_dir()
        .map_err(|e| CliError::internal(format!("failed to resolve current directory: {e}")))
}

pub fn render_systemd_unit(
    spec: &GatewayServiceInstallSpec,
    platform: &ServicePlatform,
    environment_file: Option<&Path>,
) -> Result<String, CliError> {
    let exe = service_binary_path(spec)?;
    let working_dir = service_working_directory(platform)?;
    let args = command_args(spec)?;
    let exec_start = std::iter::once(exe)
        .chain(args)
        .map(|value| systemd_quote(&value))
        .collect::<Vec<_>>()
        .join(" ");
    let system_scope = platform.scope() == ServiceScope::System;

    let mut unit = String::from(
        "[Unit]\nDescription=Verdictan gateway service\nDocumentation=https://docs.verdictan.com\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\n",
    );
    if system_scope {
        unit.push_str(&format!("User={SYSTEM_SERVICE_USER}\n"));
        unit.push_str(&format!("Group={SYSTEM_SERVICE_USER}\n"));
    }
    unit.push_str(&format!(
        "WorkingDirectory={}\n",
        systemd_quote(&working_dir.display().to_string())
    ));
    unit.push_str(&format!("ExecStart={}\n", exec_start));
    unit.push_str("Restart=on-failure\nRestartSec=3\n");

    // The environment file carries the credentials at mode 0600, so the unit
    // itself stays world readable without exposing a token. `None` means the
    // service has no environment to set at all.
    if let Some(path) = environment_file {
        for (key, value) in &merged_service_env(spec) {
            validate_systemd_env_value(key, value)?;
        }
        unit.push_str(&format!("EnvironmentFile={}\n", path.display()));
    }

    if system_scope {
        unit.push_str(
            "\n# Hardening\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=true\nReadWritePaths=/var/log\n",
        );
    }

    let wanted_by = if system_scope {
        "multi-user.target"
    } else {
        "default.target"
    };
    unit.push_str(&format!("\n[Install]\nWantedBy={wanted_by}\n"));
    Ok(unit)
}

pub fn command_args(
    spec: &GatewayServiceInstallSpec,
) -> Result<impl Iterator<Item = String>, CliError> {
    if let Some(args) = &spec.command_override {
        return Ok(args.clone().into_iter());
    }

    let mut args = vec![
        "gateway".to_string(),
        "run".to_string(),
        "--listen".to_string(),
        spec.listen.clone(),
        "--fail-mode".to_string(),
        spec.fail_mode.clone(),
    ];
    if !spec.connected_mode {
        let upstream = spec
            .upstream
            .clone()
            .unwrap_or_else(|| super::gateway_run::DEFAULT_HOSTED_UPSTREAM_URL.to_string());
        args.push("--upstream".to_string());
        args.push(upstream);
    }
    for policy_config in &spec.policy_configs {
        let canonical = canonicalize_lossy(policy_config)?;
        args.push("--policy-config".to_string());
        args.push(canonical);
    }
    if let Some(max_concurrency) = spec.max_concurrency {
        args.push("--max-concurrency".to_string());
        args.push(max_concurrency.to_string());
    }
    Ok(args.into_iter())
}

fn canonicalize_lossy(path: &Path) -> Result<String, CliError> {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .into_os_string()
        .into_string()
        .map_err(|_| CliError::user(format!("path contains invalid UTF-8: {}", path.display())))
}

/// One command that service activation or deactivation runs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceCommand {
    program: String,
    args: Vec<String>,
    /// True when a non-zero status must fail the operation.
    strict: bool,
}

impl ServiceCommand {
    fn strict(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|value| (*value).to_string()).collect(),
            strict: true,
        }
    }

    fn lenient(program: &str, args: &[&str]) -> Self {
        Self {
            strict: false,
            ..Self::strict(program, args)
        }
    }
}

fn unit_name(name: &str) -> String {
    format!("{}.service", sanitize_service_name(name))
}

/// Prefixes a `systemctl` or `journalctl` invocation with `--user` for a
/// user-scope unit.
fn systemctl_args(platform: &ServicePlatform, args: &[&str]) -> Vec<String> {
    let mut all = Vec::with_capacity(args.len() + 1);
    if platform.scope() == ServiceScope::User {
        all.push("--user".to_string());
    }
    all.extend(args.iter().map(|value| (*value).to_string()));
    all
}

/// Commands that enable a service and start it now.
///
/// A user-scope systemd unit also enables linger, because a unit that only
/// exists inside a login session stops at logout and does not return after a
/// headless reboot.
fn activation_commands(
    platform: &ServicePlatform,
    name: &str,
    service_file: &Path,
) -> Result<Vec<ServiceCommand>, CliError> {
    let safe_name = require_safe_service_name(name)?;
    Ok(match platform {
        ServicePlatform::Launchd | ServicePlatform::LaunchDaemon => {
            let domain = launchctl_domain(platform)?;
            let target = format!("{domain}/{}", service_label(&safe_name));
            vec![
                ServiceCommand::lenient("launchctl", &["bootout", &target]),
                ServiceCommand::strict(
                    "launchctl",
                    &["bootstrap", &domain, &service_file.display().to_string()],
                ),
                ServiceCommand::strict("launchctl", &["kickstart", "-k", &target]),
            ]
        }
        ServicePlatform::SystemdUser => {
            let unit = unit_name(&safe_name);
            vec![
                ServiceCommand::strict("systemctl", &["--user", "daemon-reload"]),
                ServiceCommand::strict("loginctl", &["enable-linger"]),
                ServiceCommand::strict("systemctl", &["--user", "enable", "--now", &unit]),
            ]
        }
        ServicePlatform::SystemdSystem => {
            let unit = unit_name(&safe_name);
            vec![
                ServiceCommand::strict("systemctl", &["daemon-reload"]),
                ServiceCommand::strict("systemctl", &["enable", "--now", &unit]),
            ]
        }
        ServicePlatform::WindowsService => {
            vec![ServiceCommand::strict("sc.exe", &["start", &safe_name])]
        }
    })
}

fn deactivation_commands(
    platform: &ServicePlatform,
    name: &str,
) -> Result<Vec<ServiceCommand>, CliError> {
    let safe_name = require_safe_service_name(name)?;
    Ok(match platform {
        ServicePlatform::Launchd | ServicePlatform::LaunchDaemon => {
            let target = format!(
                "{}/{}",
                launchctl_domain(platform)?,
                service_label(&safe_name)
            );
            vec![ServiceCommand::lenient("launchctl", &["bootout", &target])]
        }
        ServicePlatform::SystemdUser => vec![ServiceCommand::lenient(
            "systemctl",
            &["--user", "disable", "--now", &unit_name(&safe_name)],
        )],
        ServicePlatform::SystemdSystem => vec![ServiceCommand::lenient(
            "systemctl",
            &["disable", "--now", &unit_name(&safe_name)],
        )],
        ServicePlatform::WindowsService => {
            vec![ServiceCommand::lenient("sc.exe", &["stop", &safe_name])]
        }
    })
}

fn run_service_commands(commands: &[ServiceCommand]) -> Result<(), CliError> {
    for command in commands {
        let args = command
            .args
            .iter()
            .map(String::as_str)
            .collect::<Vec<&str>>();
        run_command(&command.program, &args, command.strict)?;
    }
    Ok(())
}

fn activate_service(
    platform: &ServicePlatform,
    name: &str,
    service_file: &Path,
) -> Result<(), CliError> {
    run_service_commands(&activation_commands(platform, name, service_file)?)
}

fn deactivate_service(
    platform: &ServicePlatform,
    name: &str,
    service_file: &Path,
) -> Result<(), CliError> {
    let _ = service_file;
    run_service_commands(&deactivation_commands(platform, name)?)
}

/// Command that reports whether a service reached the active state.
fn active_state_command(
    platform: &ServicePlatform,
    name: &str,
) -> Result<ServiceCommand, CliError> {
    let safe_name = require_safe_service_name(name)?;
    Ok(match platform {
        ServicePlatform::Launchd | ServicePlatform::LaunchDaemon => {
            let target = format!(
                "{}/{}",
                launchctl_domain(platform)?,
                service_label(&safe_name)
            );
            ServiceCommand::lenient("launchctl", &["print", &target])
        }
        ServicePlatform::SystemdUser | ServicePlatform::SystemdSystem => {
            let args = systemctl_args(platform, &["is-active", &unit_name(&safe_name)]);
            let args = args.iter().map(String::as_str).collect::<Vec<&str>>();
            ServiceCommand::lenient("systemctl", &args)
        }
        ServicePlatform::WindowsService => {
            ServiceCommand::lenient("sc.exe", &["query", &safe_name])
        }
    })
}

/// Reads the active state out of the state command's output.
///
/// Returns the observed state when the service is running, and an error string
/// that names the observed state when it is not.
fn interpret_active_state(
    platform: &ServicePlatform,
    succeeded: bool,
    stdout: &str,
) -> Result<String, String> {
    match platform {
        ServicePlatform::Launchd | ServicePlatform::LaunchDaemon => {
            if succeeded && stdout.contains("state = running") {
                Ok("running".to_string())
            } else if succeeded {
                Err("loaded".to_string())
            } else {
                Err("not_loaded".to_string())
            }
        }
        ServicePlatform::SystemdUser | ServicePlatform::SystemdSystem => {
            let state = stdout.trim();
            if state == "active" {
                Ok(state.to_string())
            } else if state.is_empty() {
                Err("unknown".to_string())
            } else {
                Err(state.to_string())
            }
        }
        ServicePlatform::WindowsService => match parse_sc_query_state(stdout) {
            Some(state) if state == "RUNNING" => Ok(state),
            Some(state) => Err(state),
            None => Err("unknown".to_string()),
        },
    }
}

/// Fails the install when the service does not reach the active state, and
/// includes the service log tail so the operator does not have to guess.
fn verify_service_is_active(platform: &ServicePlatform, name: &str) -> Result<(), CliError> {
    let command = active_state_command(platform, name)?;
    let args = command
        .args
        .iter()
        .map(String::as_str)
        .collect::<Vec<&str>>();

    let Some(output) = run_probe_command(&command.program, &args)? else {
        return Ok(());
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    match interpret_active_state(platform, output.status.success(), &stdout) {
        Ok(_) => Ok(()),
        Err(state) => Err(CliError::user(format!(
            "service {name} did not reach the active state on {} (observed: {state}){}",
            platform.display_name(),
            service_log_tail(platform, name)
        ))),
    }
}

/// Returns a short log tail for a failure message, or an empty string when the
/// platform gives no log command.
fn service_log_tail(platform: &ServicePlatform, name: &str) -> String {
    if !platform.is_systemd() {
        return String::new();
    }
    let Ok(safe_name) = require_safe_service_name(name) else {
        return String::new();
    };
    let unit = unit_name(&safe_name);
    let args = systemctl_args(platform, &["-u", &unit, "-n", "20", "--no-pager"]);
    let args = args.iter().map(String::as_str).collect::<Vec<&str>>();
    match run_probe_command("journalctl", &args) {
        Ok(Some(output)) => {
            let tail = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if tail.is_empty() {
                String::new()
            } else {
                format!("\nrecent log lines:\n{tail}")
            }
        }
        _ => String::new(),
    }
}

fn launchctl_status(
    platform: &ServicePlatform,
    label: &str,
    service_file: PathBuf,
) -> Result<ServiceStatus, CliError> {
    let target = format!("{}/{}", launchctl_domain(platform)?, label);
    let output = command_output("launchctl", &["print", &target], false)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pid = parse_launchctl_pid(&stdout);
    let state = if output.status.success() {
        if stdout.contains("state = running") {
            "running"
        } else {
            "loaded"
        }
    } else if service_file.exists() {
        "installed"
    } else {
        "not_installed"
    };

    Ok(ServiceStatus {
        platform: platform.clone(),
        label: label.to_string(),
        state: state.to_string(),
        pid,
        service_file,
    })
}

fn systemd_status(
    platform: &ServicePlatform,
    name: &str,
    service_file: PathBuf,
) -> Result<ServiceStatus, CliError> {
    let unit = unit_name(name);
    let args = systemctl_args(
        platform,
        &["show", "--property=ActiveState,SubState,MainPID", &unit],
    );
    let args = args.iter().map(String::as_str).collect::<Vec<&str>>();
    let output = command_output("systemctl", &args, false)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let active_state = parse_key_value(&stdout, "ActiveState").unwrap_or_else(|| {
        if service_file.exists() {
            "installed".to_string()
        } else {
            "not_installed".to_string()
        }
    });
    let sub_state = parse_key_value(&stdout, "SubState");
    let pid = parse_key_value(&stdout, "MainPID")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid > 0);
    Ok(ServiceStatus {
        platform: platform.clone(),
        label: unit,
        state: sub_state
            .map(|sub| format!("{active_state}/{sub}"))
            .unwrap_or(active_state),
        pid,
        service_file,
    })
}

/// Creates the dedicated system account that a system-scope Linux unit runs as.
fn ensure_system_service_user(user: &str) -> Result<(), CliError> {
    if let Some(output) = run_probe_command("id", &["-u", user])? {
        if output.status.success() {
            return Ok(());
        }
    }

    run_command(
        "useradd",
        &[
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            user,
        ],
        true,
    )
}

fn parse_launchctl_pid(stdout: &str) -> Option<u32> {
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("pid = "))
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|pid| *pid > 0)
}

fn parse_key_value(stdout: &str, key: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let (left, right) = line.split_once('=')?;
        (left.trim() == key).then(|| right.trim().to_string())
    })
}

/// launchd domain that owns the service. A LaunchDaemon lives in the `system`
/// domain, and a LaunchAgent lives in the invoking user's GUI domain.
fn launchctl_domain(platform: &ServicePlatform) -> Result<String, CliError> {
    if platform.scope() == ServiceScope::System {
        return Ok("system".to_string());
    }

    let uid = std::env::var("UID").or_else(|_| {
        command_output("id", &["-u"], true)
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
    })?;
    Ok(format!("gui/{uid}"))
}

/// Runs a command whose exit status the caller inspects.
///
/// Returns `None` when the test command-log seam replaced service management,
/// because there is then no real service to inspect.
fn run_probe_command(
    program: &str,
    args: &[&str],
) -> Result<Option<std::process::Output>, CliError> {
    #[cfg(any(test, verdictan_cli_e2e))]
    if let Some(log_path) = test_command_log_path() {
        record_test_command(&log_path, program, args)?;
        return Ok(None);
    }

    command_output(program, args, false).map(Some)
}

/// Test seam for service management. The override is compiled only into the
/// crate's own test harness, so a shipped binary cannot disable service
/// registration.
#[cfg(any(test, verdictan_cli_e2e))]
fn test_command_log_path() -> Option<String> {
    std::env::var("VERDICTAN_TEST_SERVICE_COMMAND_LOG").ok()
}

fn run_command(program: &str, args: &[&str], strict: bool) -> Result<(), CliError> {
    #[cfg(any(test, verdictan_cli_e2e))]
    if let Some(log_path) = test_command_log_path() {
        record_test_command(&log_path, program, args)?;
        return Ok(());
    }

    let output = command_output(program, args, strict)?;
    check_command_status(program, &output, strict)
}

/// Runs a command with extra environment variables, and always strictly.
///
/// The extra variables carry secret material, so they are never recorded by the
/// test command log and never appear in an error message.
fn run_command_with_env(
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
) -> Result<(), CliError> {
    #[cfg(any(test, verdictan_cli_e2e))]
    if let Some(log_path) = test_command_log_path() {
        record_test_command(&log_path, program, args)?;
        return Ok(());
    }

    let output = Command::new(program)
        .args(args)
        .envs(env.iter().copied())
        .output()
        .map_err(|e| CliError::internal(format!("failed to run {program}: {e}")))?;
    check_command_status(program, &output, true)
}

fn check_command_status(
    program: &str,
    output: &std::process::Output,
    strict: bool,
) -> Result<(), CliError> {
    if strict && !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = if stderr.trim().is_empty() {
            format!("{program} failed with status {}", output.status)
        } else {
            format!("{program} failed: {}", stderr.trim())
        };
        return Err(CliError::internal(message));
    }
    Ok(())
}

#[cfg(any(test, verdictan_cli_e2e))]
fn record_test_command(log_path: &str, program: &str, args: &[&str]) -> Result<(), CliError> {
    let line = std::iter::once(program.to_string())
        .chain(args.iter().map(|value| value.to_string()))
        .collect::<Vec<_>>()
        .join("\t");

    let path = PathBuf::from(log_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CliError::internal(format!(
                "failed to create command log directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| {
            CliError::internal(format!(
                "failed to open command log {}: {e}",
                path.display()
            ))
        })?;
    writeln!(file, "{}", line).map_err(|e| {
        CliError::internal(format!(
            "failed to write command log {}: {e}",
            path.display()
        ))
    })
}

fn command_output(
    program: &str,
    args: &[&str],
    strict_spawn: bool,
) -> Result<std::process::Output, CliError> {
    Command::new(program).args(args).output().map_err(|e| {
        let message = format!("failed to run {program}: {e}");
        if strict_spawn {
            CliError::internal(message)
        } else {
            CliError::user(message)
        }
    })
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn systemd_quote(input: &str) -> String {
    format!("\"{}\"", systemd_escape(input))
}

fn systemd_escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

// --- Windows service backend ---

/// Restart policy that `sc.exe failure` applies on Windows.
const WINDOWS_FAILURE_ACTIONS: &str = "restart/5000/restart/10000/restart/30000";
const WINDOWS_FAILURE_RESET_SECONDS: &str = "86400";

/// Builds the `binPath=` value for a Windows service registration.
///
/// The executable and every argument that holds a space get quotation marks,
/// because the service control manager splits the value on whitespace.
fn windows_service_bin_path(spec: &GatewayServiceInstallSpec) -> Result<String, CliError> {
    let exe = service_binary_path(spec)?;
    let mut parts = vec![windows_quote(&exe)];
    for arg in command_args(spec)? {
        parts.push(windows_quote(&arg));
    }
    Ok(parts.join(" "))
}

fn windows_quote(value: &str) -> String {
    if value.contains(' ') || value.contains('\t') {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

/// Environment variables that carry the registry write into PowerShell.
const WINDOWS_ENV_BLOCK_VAR: &str = "VERDICTAN_SERVICE_ENV_BLOCK";
const WINDOWS_ENV_SERVICE_VAR: &str = "VERDICTAN_SERVICE_REGISTRY_NAME";

/// PowerShell that sets the service `Environment` value with
/// `Set-ItemProperty... -Type MultiString`.
///
/// The service name and the environment block arrive through the child process
/// environment instead of the command line, because a Windows command line is
/// readable by any account on the host while a process environment block is
/// not.
const WINDOWS_SERVICE_ENV_SCRIPT: &str = concat!(
    "$ErrorActionPreference = 'Stop'; ",
    "$name = $env:VERDICTAN_SERVICE_REGISTRY_NAME; ",
    "$block = $env:VERDICTAN_SERVICE_ENV_BLOCK -split \"`n\"; ",
    "Set-ItemProperty ",
    "-Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$name\" ",
    "-Name 'Environment' -Value $block -Type MultiString",
);

/// Renders the `REG_MULTI_SZ` entries as one newline-separated block.
///
/// `validate_windows_env_value` refuses a control character, so a newline can
/// only come from this function and the split stays unambiguous.
fn render_windows_service_environment_block(
    env: &BTreeMap<String, String>,
) -> Result<String, CliError> {
    let mut lines = Vec::with_capacity(env.len());
    for (key, value) in env {
        validate_windows_env_value(key, value)?;
        lines.push(format!("{key}={value}"));
    }
    Ok(lines.join("\n"))
}

/// A control character would split one `REG_MULTI_SZ` entry into two and inject
/// an extra assignment, so the render refuses one.
fn validate_windows_env_value(name: &str, value: &str) -> Result<(), CliError> {
    if contains_control_characters(value) {
        return Err(CliError::user(format!(
            "{name} contains unsupported control characters for windows service installation"
        )));
    }
    Ok(())
}

/// Reads the service state out of `sc.exe query` output.
fn parse_sc_query_state(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let (left, right) = line.split_once(':')?;
        if left.trim() != "STATE" {
            return None;
        }
        right.split_whitespace().nth(1).map(str::to_string)
    })
}

fn windows_service_is_registered(name: &str) -> Result<bool, CliError> {
    let safe_name = require_safe_service_name(name)?;
    match run_probe_command("sc.exe", &["query", &safe_name])? {
        Some(output) => Ok(output.status.success()),
        // The command-log seam replaced service management, so there is no
        // registration to observe.
        None => Ok(false),
    }
}

fn windows_service_status(name: &str, service_file: PathBuf) -> Result<ServiceStatus, CliError> {
    let safe_name = require_safe_service_name(name)?;
    let output = command_output("sc.exe", &["query", &safe_name], false)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let state = match parse_sc_query_state(&stdout) {
        Some(state) => state.to_ascii_lowercase(),
        None => "not_installed".to_string(),
    };
    Ok(ServiceStatus {
        platform: ServicePlatform::WindowsService,
        label: safe_name,
        state,
        pid: None,
        service_file,
    })
}

/// Registers or updates a Windows service and returns its registry key.
///
/// The install writes the service registration, the `HKLM` environment block,
/// and the restart policy.
fn install_windows_service(spec: &GatewayServiceInstallSpec) -> Result<PathBuf, CliError> {
    let safe_name = require_safe_service_name(&spec.name)?;
    let bin_path = windows_service_bin_path(spec)?;
    let display_name = format!("Verdictan Gateway ({safe_name})");

    if windows_service_is_registered(&safe_name)? {
        run_command("sc.exe", &["stop", &safe_name], false)?;
        run_command(
            "sc.exe",
            &[
                "config", &safe_name, "binPath=", &bin_path, "start=", "auto",
            ],
            true,
        )?;
    } else {
        run_command(
            "sc.exe",
            &[
                "create",
                &safe_name,
                "binPath=",
                &bin_path,
                "start=",
                "auto",
                "DisplayName=",
                &display_name,
            ],
            true,
        )?;
    }

    run_command(
        "sc.exe",
        &[
            "description",
            &safe_name,
            "Verdictan gateway service running verdictan gateway run",
        ],
        false,
    )?;

    let env = merged_service_env(spec);
    if !env.is_empty() {
        apply_windows_service_environment(&safe_name, &env)?;
    }

    run_command(
        "sc.exe",
        &[
            "failure",
            &safe_name,
            "reset=",
            WINDOWS_FAILURE_RESET_SECONDS,
            "actions=",
            WINDOWS_FAILURE_ACTIONS,
        ],
        true,
    )?;

    let service_file = service_file_path(&ServicePlatform::WindowsService, &safe_name)?;
    activate_service(&ServicePlatform::WindowsService, &safe_name, &service_file)?;
    Ok(service_file)
}

/// Sets the `HKLM` service environment block.
///
/// The credential never reaches a command line and never reaches a file. It
/// goes to PowerShell in the child process environment, so the registry value
/// is the only place it comes to rest.
fn apply_windows_service_environment(
    safe_name: &str,
    env: &BTreeMap<String, String>,
) -> Result<(), CliError> {
    let block = render_windows_service_environment_block(env)?;
    run_command_with_env(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            WINDOWS_SERVICE_ENV_SCRIPT,
        ],
        &[
            (WINDOWS_ENV_SERVICE_VAR, safe_name),
            (WINDOWS_ENV_BLOCK_VAR, &block),
        ],
    )
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
    use super::{
        activate_service, activation_commands, build_install_plan, candidate_platforms,
        canonicalize_lossy, command_args, current_platform, deactivate_service,
        deactivation_commands, env_carries_secret_material, environment_file_path, install_service,
        interpret_active_state, is_secret_env_key, launchctl_domain, logs_dir, merged_service_env,
        parse_key_value, parse_launchctl_pid, parse_sc_query_state, render_launchd_plist,
        render_systemd_environment_file, render_systemd_unit,
        render_windows_service_environment_block, resolve_platform, run_command,
        sanitize_service_name, service_file_exists, service_file_path, service_status,
        service_working_directory, start_service, stop_service, systemd_escape, uninstall_service,
        windows_quote, windows_service_bin_path, xml_escape, GatewayServiceInstallSpec,
        ServicePlatform, ServiceScope, SYSTEMD_SYSTEM_UNIT_DIR, SYSTEM_CONFIG_DIR,
        SYSTEM_SERVICE_USER,
    };
    use std::{
        collections::BTreeMap,
        ffi::OsString,
        path::{Path, PathBuf},
    };

    #[cfg(unix)]
    use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt};

    pub(super) struct TestEnvGuard {
        previous: Vec<(&'static str, Option<OsString>)>,
    }

    impl TestEnvGuard {
        pub(super) fn new(pairs: &[(&'static str, String)]) -> Self {
            let previous = pairs
                .iter()
                .map(|(key, _)| (*key, std::env::var_os(key)))
                .collect();
            for (key, value) in pairs {
                crate::test_support::set_var(key, value);
            }
            Self { previous }
        }
    }

    struct UnsetEnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl UnsetEnvGuard {
        fn new(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            crate::test_support::unset_var(key);
            Self { key, previous }
        }
    }

    impl Drop for UnsetEnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => crate::test_support::set_var(self.key, value),
                None => crate::test_support::unset_var(self.key),
            }
        }
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            for (key, previous) in self.previous.iter().rev() {
                match previous {
                    Some(value) => crate::test_support::set_var(key, value),
                    None => crate::test_support::unset_var(key),
                }
            }
        }
    }

    pub(super) fn sample_spec() -> GatewayServiceInstallSpec {
        GatewayServiceInstallSpec {
            name: "finance-main".to_string(),
            listen: "127.0.0.1:41002".to_string(),
            upstream: Some("https://api.example.com".to_string()),
            policy_configs: vec![PathBuf::from("policy.yaml")],
            fail_mode: "block".to_string(),
            max_concurrency: Some(8),
            connected_mode: false,
            api_token: Some("service-token".to_string()),
            agent_id: Some("agent-123".to_string()),
            env: BTreeMap::from([(
                "VERDICTAN_API_URL".to_string(),
                "https://cp.example.com".to_string(),
            )]),
            command_override: None,
            binary_path_override: None,
        }
    }

    fn read_command_log(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .expect("command log")
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[cfg(unix)]
    fn write_fake_command(bin_dir: &Path, program: &str, body: &str) {
        let path = bin_dir.join(program);
        std::fs::create_dir_all(bin_dir).expect("bin dir");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&path, permissions).expect("chmod");
    }

    #[test]
    fn merged_service_env_includes_non_empty_agent_and_token() {
        let env = merged_service_env(&sample_spec());

        assert_eq!(
            env.get("VERDICTAN_AGENT_ID").map(String::as_str),
            Some("agent-123")
        );
        assert_eq!(
            env.get("VERDICTAN_API_TOKEN").map(String::as_str),
            Some("service-token")
        );
        assert_eq!(
            env.get("VERDICTAN_API_URL").map(String::as_str),
            Some("https://cp.example.com")
        );
    }

    #[test]
    fn merged_service_env_skips_blank_overrides() {
        let mut spec = sample_spec();
        spec.api_token = Some("   ".to_string());
        spec.agent_id = Some("\n\t".to_string());

        let env = merged_service_env(&spec);

        assert!(!env.contains_key("VERDICTAN_AGENT_ID"));
        assert!(!env.contains_key("VERDICTAN_API_TOKEN"));
    }

    #[test]
    fn sanitize_service_name_and_service_file_paths_are_stable() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = TestEnvGuard::new(&[(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        )]);

        assert_eq!(
            sanitize_service_name(" finance/main@prod "),
            "finance-main-prod"
        );
        assert_eq!(sanitize_service_name("___gateway___"), "___gateway___");

        assert_eq!(
            service_file_path(&ServicePlatform::Launchd, " finance/main@prod ")
                .expect("launchd path"),
            dir.path()
                .join("Library/LaunchAgents/com.verdictan.gateway.finance-main-prod.plist")
        );
        assert_eq!(
            service_file_path(&ServicePlatform::SystemdUser, " finance/main@prod ")
                .expect("systemd path"),
            dir.path()
                .join(".config/systemd/user/finance-main-prod.service")
        );

        let err = service_file_path(&ServicePlatform::Launchd, "!!!")
            .expect_err("empty sanitized name should fail");
        assert!(err
            .to_string()
            .contains("service name must contain at least one valid character"));
    }

    #[test]
    fn command_args_build_default_gateway_invocation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_config = dir.path().join("policy.yaml");
        std::fs::write(&policy_config, "version: 1\n").expect("policy file");

        let mut spec = sample_spec();
        spec.upstream = None;
        spec.policy_configs = vec![policy_config.clone()];

        let args = command_args(&spec)
            .expect("command args")
            .collect::<Vec<_>>();

        assert_eq!(
            args,
            vec![
                "gateway".to_string(),
                "run".to_string(),
                "--listen".to_string(),
                "127.0.0.1:41002".to_string(),
                "--fail-mode".to_string(),
                "block".to_string(),
                "--upstream".to_string(),
                crate::commands::gateway_run::DEFAULT_HOSTED_UPSTREAM_URL.to_string(),
                "--policy-config".to_string(),
                canonicalize_lossy(&policy_config).expect("canonical policy path"),
                "--max-concurrency".to_string(),
                "8".to_string(),
            ]
        );
    }

    #[test]
    fn command_args_omit_upstream_for_connected_mode_and_respect_override() {
        let mut spec = sample_spec();
        spec.connected_mode = true;
        spec.max_concurrency = None;
        spec.policy_configs.clear();

        let connected_args = command_args(&spec)
            .expect("connected command args")
            .collect::<Vec<_>>();
        assert!(!connected_args.iter().any(|arg| arg == "--upstream"));

        spec.command_override = Some(vec![
            "custom-supervisor".to_string(),
            "--state-dir".to_string(),
            "/tmp/state".to_string(),
        ]);
        let override_args = command_args(&spec)
            .expect("override args")
            .collect::<Vec<_>>();
        assert_eq!(
            override_args,
            vec![
                "custom-supervisor".to_string(),
                "--state-dir".to_string(),
                "/tmp/state".to_string(),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonicalize_lossy_rejects_invalid_utf8_paths() {
        let path = PathBuf::from(OsString::from_vec(vec![0xff, b'o', b'k']));
        let err = canonicalize_lossy(&path).expect_err("invalid utf-8 path");
        assert!(err.to_string().contains("path contains invalid UTF-8"));
    }

    #[test]
    fn render_launchd_plist_includes_logs_policy_args_and_escaped_env() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_config = dir.path().join("policy.yaml");
        std::fs::write(&policy_config, "version: 1\n").expect("policy file");
        let _env = TestEnvGuard::new(&[(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        )]);

        let mut spec = sample_spec();
        spec.policy_configs = vec![policy_config.clone()];
        spec.api_token = Some("token<&>".to_string());
        spec.agent_id = Some("agent<&>".to_string());
        spec.env
            .insert("SPECIAL".to_string(), "one & two \" <three>".to_string());

        let plist = render_launchd_plist(&spec, &ServicePlatform::Launchd).expect("launchd plist");

        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains(&xml_escape(
            &canonicalize_lossy(&policy_config).expect("canonical policy path"),
        )));
        assert!(plist.contains(&xml_escape(
            &dir.path()
                .join(".verdictan/logs/finance-main.out.log")
                .display()
                .to_string(),
        )));
        assert!(plist.contains("<key>VERDICTAN_API_TOKEN</key>"));
        assert!(plist.contains(&xml_escape("token<&>")));
        assert!(plist.contains("<key>SPECIAL</key>"));
        assert!(plist.contains(&xml_escape("one & two \" <three>")));
    }

    #[test]
    fn render_launchd_plist_rejects_newline_and_control_characters() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = TestEnvGuard::new(&[(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        )]);

        let mut newline_spec = sample_spec();
        newline_spec.env.insert(
            "VERDICTAN_API_URL".to_string(),
            "https://api.example.test\n$(whoami)".to_string(),
        );
        let newline_err = render_launchd_plist(&newline_spec, &ServicePlatform::Launchd)
            .expect_err("newline env must fail closed");
        assert!(newline_err
            .to_string()
            .contains("unsupported control characters for launchd"));

        let mut control_spec = sample_spec();
        control_spec
            .env
            .insert("SPECIAL".to_string(), "value\u{0007}bell".to_string());
        let control_err = render_launchd_plist(&control_spec, &ServicePlatform::Launchd)
            .expect_err("control env must fail closed");
        assert!(control_err
            .to_string()
            .contains("unsupported control characters for launchd"));
    }

    #[test]
    fn render_launchd_plist_keeps_quote_substitution_and_semicolon_literal() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = TestEnvGuard::new(&[(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        )]);

        let mut spec = sample_spec();
        spec.api_token = Some(r#"tok"; touch /tmp/x; #"#.to_string());
        spec.env.insert(
            "VERDICTAN_API_URL".to_string(),
            r#"$(touch /tmp/pwned);value"quoted""#.to_string(),
        );
        spec.env.insert(
            "SPECIAL".to_string(),
            r#"semi;colon & quoted "value""#.to_string(),
        );

        let plist = render_launchd_plist(&spec, &ServicePlatform::Launchd)
            .expect("literal hostile values must encode");
        assert!(plist.contains("<key>EnvironmentVariables</key>"));
        assert!(plist.contains(&xml_escape(r#"tok"; touch /tmp/x; #"#)));
        assert!(plist.contains(&xml_escape(r#"$(touch /tmp/pwned);value"quoted""#)));
        assert!(plist.contains(&xml_escape(r#"semi;colon & quoted "value""#)));
        assert!(!plist.contains(".env</string>"));
        assert!(!plist.contains("<string>/bin/sh</string>"));
    }

    #[test]
    fn render_systemd_unit_quotes_args_and_escapes_env() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_config = dir.path().join("policy.yaml");
        std::fs::write(&policy_config, "version: 1\n").expect("policy file");

        let mut spec = sample_spec();
        spec.connected_mode = true;
        spec.max_concurrency = None;
        spec.policy_configs = vec![policy_config.clone()];
        spec.env.insert(
            "SPECIAL".to_string(),
            "value \"quoted\" \\ tail".to_string(),
        );

        let env_file = PathBuf::from("/home/dev/.config/verdictan/finance-main.env");
        let unit = render_systemd_unit(&spec, &ServicePlatform::SystemdUser, Some(&env_file))
            .expect("systemd unit");

        assert!(unit.contains("ExecStart="));
        assert!(unit.contains("\"gateway\" \"run\""));
        assert!(unit.contains(&format!(
            "\"{}\"",
            canonicalize_lossy(&policy_config).expect("canonical policy path"),
        )));
        assert!(!unit.contains("\"--upstream\""));
        assert!(unit.contains("EnvironmentFile=/home/dev/.config/verdictan/finance-main.env"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(!unit.contains("User="));
        assert!(!unit.contains("NoNewPrivileges="));
    }

    #[test]
    fn render_systemd_unit_rejects_a_control_character_in_an_env_value() {
        let mut spec = sample_spec();
        spec.env
            .insert("SPECIAL".to_string(), "value\u{0007}bell".to_string());
        let env_file = PathBuf::from("/etc/verdictan/finance-main.env");

        let err = render_systemd_unit(&spec, &ServicePlatform::SystemdSystem, Some(&env_file))
            .expect_err("a control character must fail closed");
        assert!(err
            .to_string()
            .contains("unsupported control characters for systemd"));
    }

    #[test]
    fn render_systemd_unit_adds_scope_user_and_hardening_for_a_system_unit() {
        let spec = sample_spec();
        let env_file = PathBuf::from("/etc/verdictan/finance-main.env");

        let unit = render_systemd_unit(&spec, &ServicePlatform::SystemdSystem, Some(&env_file))
            .expect("systemd system unit");

        assert!(unit.contains(&format!("User={SYSTEM_SERVICE_USER}\n")));
        assert!(unit.contains(&format!("Group={SYSTEM_SERVICE_USER}\n")));
        assert!(unit.contains("WorkingDirectory=\"/\"\n"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("ProtectHome=read-only"));
        assert!(unit.contains("PrivateTmp=true"));
        assert!(unit.contains("ReadWritePaths=/var/log"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn render_systemd_unit_moves_the_token_out_of_the_unit_when_an_env_file_is_used() {
        let spec = sample_spec();
        let env_file = PathBuf::from("/etc/verdictan/finance-main.env");

        let unit = render_systemd_unit(&spec, &ServicePlatform::SystemdSystem, Some(&env_file))
            .expect("systemd system unit");

        assert!(unit.contains("EnvironmentFile=/etc/verdictan/finance-main.env"));
        assert!(
            !unit.contains("service-token"),
            "the unit must not embed the token: {unit}"
        );
        assert!(
            !unit.contains("Environment=\""),
            "an env-file unit must not inline Environment= lines: {unit}"
        );
    }

    #[test]
    fn render_systemd_environment_file_writes_one_escaped_pair_per_line() {
        let env = BTreeMap::from([
            ("VERDICTAN_API_TOKEN".to_string(), "tok\"en".to_string()),
            (
                "VERDICTAN_API_URL".to_string(),
                "https://api.test".to_string(),
            ),
        ]);

        let contents = render_systemd_environment_file(&env).expect("environment file");

        assert_eq!(
            contents,
            format!(
                "VERDICTAN_API_TOKEN=\"{}\"\nVERDICTAN_API_URL=\"{}\"\n",
                systemd_escape("tok\"en"),
                systemd_escape("https://api.test"),
            )
        );
    }

    #[test]
    fn render_systemd_environment_file_rejects_a_newline_value() {
        let env = BTreeMap::from([(
            "VERDICTAN_API_TOKEN".to_string(),
            "tok\ninjected=1".to_string(),
        )]);

        let err = render_systemd_environment_file(&env)
            .expect_err("a newline would inject a second assignment");
        assert!(err.to_string().contains("unsupported control characters"));
    }

    #[test]
    fn current_platform_rejects_invalid_test_override() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = TestEnvGuard::new(&[(
            "VERDICTAN_TEST_SERVICE_PLATFORM",
            "unsupported-platform".to_string(),
        )]);

        let err = current_platform().expect_err("invalid platform override");
        assert!(err
            .to_string()
            .contains("unsupported test service platform override"));
    }

    #[cfg(unix)]
    #[test]
    fn worker6_gateway_service_launchctl_domain_falls_back_to_id_command() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        write_fake_command(&bin_dir, "id", "printf '777\\n'");
        let path = format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let _env = TestEnvGuard::new(&[("PATH", path)]);
        let _uid = UnsetEnvGuard::new("UID");

        assert_eq!(
            launchctl_domain(&ServicePlatform::Launchd).expect("launchctl domain"),
            "gui/777"
        );
    }

    #[cfg(unix)]
    #[test]
    fn worker6_gateway_service_run_command_strict_reports_stderr_output() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        write_fake_command(&bin_dir, "fakectl", "printf 'boom\\n' >&2\nexit 1");
        let path = format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let _env = TestEnvGuard::new(&[("PATH", path)]);

        let err = run_command("fakectl", &["status"], true).expect_err("strict failure");
        assert_eq!(err.error_code(), "cli.internal");
        assert!(err.to_string().contains("boom"));
    }

    #[cfg(unix)]
    #[test]
    fn worker6_gateway_service_run_command_strict_reports_exit_status_without_stderr() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        write_fake_command(&bin_dir, "quietctl", "exit 7");
        let path = format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let _env = TestEnvGuard::new(&[("PATH", path)]);

        let err = run_command("quietctl", &["status"], true).expect_err("strict failure");
        assert_eq!(err.error_code(), "cli.internal");
        assert!(err.to_string().contains("quietctl failed with status"));
    }

    #[test]
    fn start_and_stop_service_require_installed_unit_file() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                dir.path().to_string_lossy().to_string(),
            ),
            ("VERDICTAN_TEST_SERVICE_PLATFORM", "launchd".to_string()),
            (
                "VERDICTAN_TEST_SERVICE_COMMAND_LOG",
                dir.path()
                    .join("commands.log")
                    .to_string_lossy()
                    .to_string(),
            ),
        ]);

        let start_error = start_service("finance-main").expect_err("missing service");
        assert!(start_error.to_string().contains("is not installed"));

        let stop_error = stop_service("finance-main").expect_err("missing service");
        assert!(stop_error.to_string().contains("is not installed"));
    }

    #[test]
    fn worker6_gateway_service_service_file_exists_reflects_install_state() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                dir.path().to_string_lossy().to_string(),
            ),
            (
                "VERDICTAN_TEST_SERVICE_PLATFORM",
                "systemd-user".to_string(),
            ),
        ]);

        assert!(!service_file_exists("finance-main").expect("missing service"));

        let path =
            service_file_path(&ServicePlatform::SystemdUser, "finance-main").expect("service path");
        std::fs::create_dir_all(path.parent().expect("service parent")).expect("mkdir parent");
        std::fs::write(&path, "[Service]\n").expect("seed service");

        assert!(service_file_exists("finance-main").expect("existing service"));
    }

    #[test]
    fn launchd_service_lifecycle_writes_expected_files_and_commands() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let command_log = dir.path().join("commands.log");
        let policy_config = dir.path().join("policy.yaml");
        std::fs::write(&policy_config, "version: 1\n").expect("policy file");
        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                dir.path().to_string_lossy().to_string(),
            ),
            ("VERDICTAN_TEST_SERVICE_PLATFORM", "launchd".to_string()),
            (
                "VERDICTAN_TEST_SERVICE_COMMAND_LOG",
                command_log.to_string_lossy().to_string(),
            ),
            ("UID", "501".to_string()),
        ]);

        let mut spec = sample_spec();
        spec.policy_configs = vec![policy_config];

        let (platform, service_file) = install_service(&spec).expect("install service");
        assert_eq!(platform, ServicePlatform::Launchd);
        assert_eq!(
            service_file,
            dir.path()
                .join("Library/LaunchAgents/com.verdictan.gateway.finance-main.plist")
        );
        assert!(service_file.exists());

        let contents = std::fs::read_to_string(&service_file).expect("service file");
        assert!(contents.contains("com.verdictan.gateway.finance-main"));

        activate_service(&platform, "finance-main", &service_file).expect("activate service");

        deactivate_service(&platform, "finance-main", &service_file).expect("deactivate service");

        let (uninstall_platform, uninstall_file) =
            uninstall_service("finance-main").expect("uninstall service");
        assert_eq!(uninstall_platform, ServicePlatform::Launchd);
        assert_eq!(uninstall_file, service_file);
        assert!(!service_file.exists());

        let target = "gui/501/com.verdictan.gateway.finance-main";
        assert_eq!(
            read_command_log(&command_log),
            vec![
                // install: activate, then the post-install active-state probe.
                format!("launchctl\tbootout\t{target}"),
                format!("launchctl\tbootstrap\tgui/501\t{}", service_file.display()),
                format!("launchctl\tkickstart\t-k\t{target}"),
                format!("launchctl\tprint\t{target}"),
                // the explicit activate_service call above
                format!("launchctl\tbootout\t{target}"),
                format!("launchctl\tbootstrap\tgui/501\t{}", service_file.display()),
                format!("launchctl\tkickstart\t-k\t{target}"),
                // deactivate, then uninstall
                format!("launchctl\tbootout\t{target}"),
                format!("launchctl\tbootout\t{target}"),
            ]
        );
    }

    #[test]
    fn systemd_service_lifecycle_writes_expected_files_and_commands() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let command_log = dir.path().join("commands.log");
        let policy_config = dir.path().join("policy.yaml");
        std::fs::write(&policy_config, "version: 1\n").expect("policy file");
        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                dir.path().to_string_lossy().to_string(),
            ),
            (
                "VERDICTAN_TEST_SERVICE_PLATFORM",
                "systemd-user".to_string(),
            ),
            (
                "VERDICTAN_TEST_SERVICE_COMMAND_LOG",
                command_log.to_string_lossy().to_string(),
            ),
        ]);

        let mut spec = sample_spec();
        spec.policy_configs = vec![policy_config];

        let (platform, service_file) = install_service(&spec).expect("install service");
        assert_eq!(platform, ServicePlatform::SystemdUser);
        assert_eq!(
            service_file,
            dir.path().join(".config/systemd/user/finance-main.service")
        );
        assert!(service_file.exists());

        activate_service(&platform, "finance-main", &service_file).expect("activate service");

        deactivate_service(&platform, "finance-main", &service_file).expect("deactivate service");

        let (uninstall_platform, uninstall_file) =
            uninstall_service("finance-main").expect("uninstall service");
        assert_eq!(uninstall_platform, ServicePlatform::SystemdUser);
        assert_eq!(uninstall_file, service_file);
        assert!(!service_file.exists());

        assert_eq!(
            read_command_log(&command_log),
            vec![
                // install: linger keeps the unit alive across a logout, and the
                // probe confirms the unit reached the active state.
                "systemctl\t--user\tdaemon-reload".to_string(),
                "loginctl\tenable-linger".to_string(),
                "systemctl\t--user\tenable\t--now\tfinance-main.service".to_string(),
                "systemctl\t--user\tis-active\tfinance-main.service".to_string(),
                // the explicit activate_service call above
                "systemctl\t--user\tdaemon-reload".to_string(),
                "loginctl\tenable-linger".to_string(),
                "systemctl\t--user\tenable\t--now\tfinance-main.service".to_string(),
                // deactivate, then uninstall
                "systemctl\t--user\tdisable\t--now\tfinance-main.service".to_string(),
                "systemctl\t--user\tdisable\t--now\tfinance-main.service".to_string(),
                "systemctl\t--user\tdaemon-reload".to_string(),
            ]
        );
    }

    /// The user-scope environment file must exist beside the unit and hold the
    /// token, so that the unit itself carries no credential.
    #[cfg(unix)]
    #[test]
    fn systemd_user_install_writes_a_private_environment_file_beside_the_unit() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let command_log = dir.path().join("commands.log");
        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                dir.path().to_string_lossy().to_string(),
            ),
            (
                "VERDICTAN_TEST_SERVICE_PLATFORM",
                "systemd-user".to_string(),
            ),
            (
                "VERDICTAN_TEST_SERVICE_COMMAND_LOG",
                command_log.to_string_lossy().to_string(),
            ),
        ]);

        let mut spec = sample_spec();
        spec.policy_configs = vec![];

        let (_, service_file) = install_service(&spec).expect("install service");
        let environment_file = dir.path().join(".config/verdictan/finance-main.env");

        assert!(
            environment_file.exists(),
            "environment file must be written"
        );
        let env_contents = std::fs::read_to_string(&environment_file).expect("env file");
        assert!(env_contents.contains("VERDICTAN_API_TOKEN=\"service-token\""));

        let env_mode = std::fs::metadata(&environment_file)
            .expect("env metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            env_mode, 0o600,
            "the environment file holds a live token and must be owner only"
        );

        let unit = std::fs::read_to_string(&service_file).expect("unit file");
        assert!(
            !unit.contains("service-token"),
            "the unit must not embed the token: {unit}"
        );
        assert!(unit.contains(&format!("EnvironmentFile={}", environment_file.display())));

        uninstall_service("finance-main").expect("uninstall service");
        assert!(
            !environment_file.exists(),
            "the environment file must not outlive the unit"
        );
    }

    #[cfg(unix)]
    #[test]
    fn launchd_service_status_reports_running_loaded_and_install_states() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        write_fake_command(
            &bin_dir,
            "launchctl",
            "printf 'state = running\\npid = 42\\n'",
        );
        let path = format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                dir.path().to_string_lossy().to_string(),
            ),
            ("VERDICTAN_TEST_SERVICE_PLATFORM", "launchd".to_string()),
            ("UID", "501".to_string()),
            ("PATH", path),
        ]);

        let running = service_status("finance-main").expect("running status");
        assert_eq!(running.platform, ServicePlatform::Launchd);
        assert_eq!(running.label, "com.verdictan.gateway.finance-main");
        assert_eq!(running.state, "running");
        assert_eq!(running.pid, Some(42));

        write_fake_command(
            &bin_dir,
            "launchctl",
            "printf 'state = waiting\\npid = 0\\n'",
        );
        let loaded = service_status("finance-main").expect("loaded status");
        assert_eq!(loaded.state, "loaded");
        assert_eq!(loaded.pid, None);

        let service_file =
            service_file_path(&ServicePlatform::Launchd, "finance-main").expect("launchd path");
        std::fs::create_dir_all(service_file.parent().expect("service parent"))
            .expect("service parent dir");
        std::fs::write(&service_file, "plist").expect("service file");

        write_fake_command(&bin_dir, "launchctl", "exit 1");
        let installed = service_status("finance-main").expect("installed status");
        assert_eq!(installed.state, "installed");
        assert_eq!(installed.pid, None);

        std::fs::remove_file(&service_file).expect("remove service file");
        let missing = service_status("finance-main").expect("missing status");
        assert_eq!(missing.state, "not_installed");
    }

    #[cfg(unix)]
    #[test]
    fn systemd_service_status_reports_active_and_fallback_states() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        write_fake_command(
            &bin_dir,
            "systemctl",
            "printf 'ActiveState=active\\nSubState=running\\nMainPID=77\\n'",
        );
        let path = format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                dir.path().to_string_lossy().to_string(),
            ),
            (
                "VERDICTAN_TEST_SERVICE_PLATFORM",
                "systemd-user".to_string(),
            ),
            ("PATH", path),
        ]);

        let active = service_status("finance-main").expect("active status");
        assert_eq!(active.platform, ServicePlatform::SystemdUser);
        assert_eq!(active.label, "finance-main.service");
        assert_eq!(active.state, "active/running");
        assert_eq!(active.pid, Some(77));

        let service_file =
            service_file_path(&ServicePlatform::SystemdUser, "finance-main").expect("systemd path");
        std::fs::create_dir_all(service_file.parent().expect("service parent"))
            .expect("service parent dir");
        std::fs::write(&service_file, "unit").expect("service file");

        write_fake_command(&bin_dir, "systemctl", "printf ''");
        let installed = service_status("finance-main").expect("installed status");
        assert_eq!(installed.state, "installed");
        assert_eq!(installed.pid, None);

        std::fs::remove_file(&service_file).expect("remove service file");
        let missing = service_status("finance-main").expect("missing status");
        assert_eq!(missing.state, "not_installed");
    }

    #[test]
    fn is_secret_env_key_matches_credential_bearing_names_only() {
        assert!(is_secret_env_key("VERDICTAN_API_TOKEN"));
        assert!(is_secret_env_key("VERDICTAN_UPSTREAM_API_KEY"));
        assert!(is_secret_env_key("VERDICTAN_ADMIN_SECRET"));
        assert!(is_secret_env_key("verdictan_api_token"));
        assert!(!is_secret_env_key("VERDICTAN_API_URL"));
        assert!(!is_secret_env_key("VERDICTAN_AGENT_ID"));
    }

    #[test]
    fn env_carries_secret_material_ignores_blank_values() {
        assert!(env_carries_secret_material(&BTreeMap::from([(
            "VERDICTAN_API_TOKEN".to_string(),
            "live-token".to_string(),
        )])));
        assert!(!env_carries_secret_material(&BTreeMap::from([(
            "VERDICTAN_API_TOKEN".to_string(),
            "   ".to_string(),
        )])));
        assert!(!env_carries_secret_material(&BTreeMap::from([(
            "VERDICTAN_API_URL".to_string(),
            "https://cp.example.com".to_string(),
        )])));
    }

    #[cfg(unix)]
    #[test]
    fn install_service_writes_a_token_bearing_unit_with_owner_only_mode() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        // launchd has no environment-file mechanism, so the plist keeps the
        // token inline and the file mode is the only protection it has.
        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                dir.path().to_string_lossy().to_string(),
            ),
            ("VERDICTAN_TEST_SERVICE_PLATFORM", "launchd".to_string()),
            (
                "VERDICTAN_TEST_SERVICE_COMMAND_LOG",
                dir.path()
                    .join("commands.log")
                    .to_string_lossy()
                    .to_string(),
            ),
            ("UID", "501".to_string()),
        ]);

        let mut spec = sample_spec();
        spec.policy_configs.clear();

        let (_platform, service_file) = install_service(&spec).expect("install service");
        assert!(std::fs::read_to_string(&service_file)
            .expect("plist")
            .contains("service-token"));

        let mode = std::fs::metadata(&service_file)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "a unit that embeds a live token must be private"
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_service_keeps_the_default_mode_for_a_unit_without_secrets() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = TestEnvGuard::new(&[
            (
                "VERDICTAN_TEST_HOME",
                dir.path().to_string_lossy().to_string(),
            ),
            (
                "VERDICTAN_TEST_SERVICE_PLATFORM",
                "systemd-user".to_string(),
            ),
            (
                "VERDICTAN_TEST_SERVICE_COMMAND_LOG",
                dir.path()
                    .join("commands.log")
                    .to_string_lossy()
                    .to_string(),
            ),
        ]);

        let mut spec = sample_spec();
        spec.policy_configs.clear();
        spec.api_token = None;
        spec.env.clear();

        let (_platform, service_file) = install_service(&spec).expect("install service");

        let mode = std::fs::metadata(&service_file)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_ne!(mode, 0o600);
    }

    #[test]
    fn parse_helpers_extract_expected_values() {
        assert_eq!(
            parse_launchctl_pid("state = running\n pid = 42\n"),
            Some(42)
        );
        assert_eq!(parse_launchctl_pid("pid = 0\n"), None);
        assert_eq!(
            parse_key_value("ActiveState=active\nSubState=running\n", "SubState").as_deref(),
            Some("running")
        );
        assert_eq!(parse_key_value("ActiveState=active\n", "Missing"), None);
    }

    #[test]
    fn service_platform_override_round_trips_supported_values() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");

        let _launchd =
            TestEnvGuard::new(&[("VERDICTAN_TEST_SERVICE_PLATFORM", "launchd".to_string())]);
        assert_eq!(
            current_platform().expect("launchd"),
            ServicePlatform::Launchd
        );
        drop(_launchd);

        let _systemd = TestEnvGuard::new(&[(
            "VERDICTAN_TEST_SERVICE_PLATFORM",
            "systemd-user".to_string(),
        )]);
        assert_eq!(
            current_platform().expect("systemd"),
            ServicePlatform::SystemdUser
        );
    }

    #[test]
    fn xml_escape_special_characters() {
        assert_eq!(xml_escape("a<b>c&d\"e'f"), "a&lt;b&gt;c&amp;d&quot;e'f");
    }

    #[test]
    fn xml_escape_no_special_characters() {
        assert_eq!(xml_escape("hello world"), "hello world");
    }

    #[test]
    fn xml_escape_empty_string() {
        assert_eq!(xml_escape(""), "");
    }

    #[test]
    fn systemd_escape_special_characters() {
        let escaped = systemd_escape("hello \"world\"");
        assert!(escaped.contains("\\\""));
    }

    #[test]
    fn systemd_escape_empty_string() {
        assert_eq!(systemd_escape(""), "");
    }

    #[test]
    fn sanitize_service_name_replaces_invalid_chars() {
        let sanitized = sanitize_service_name("my/gateway:prod");
        assert!(!sanitized.contains('/'));
        assert!(!sanitized.contains(':'));
    }

    #[test]
    fn sanitize_service_name_preserves_valid_chars() {
        assert_eq!(sanitize_service_name("my-gateway-prod"), "my-gateway-prod");
    }

    #[test]
    fn sanitize_service_name_empty() {
        assert_eq!(sanitize_service_name(""), "");
    }

    #[test]
    fn canonicalize_lossy_handles_nonexistent_path() {
        let path = PathBuf::from("/nonexistent/test/path/binary");
        let result = canonicalize_lossy(&path).unwrap();
        assert_eq!(result, path.to_string_lossy());
    }

    #[test]
    fn merged_service_env_combines_spec_env() {
        let spec = GatewayServiceInstallSpec {
            name: "test".to_string(),
            listen: "0.0.0.0:8080".to_string(),
            upstream: Some("https://api.openai.com/v1".to_string()),
            policy_configs: vec![PathBuf::from("policy.yaml")],
            fail_mode: "block".to_string(),
            max_concurrency: None,
            connected_mode: false,
            api_token: None,
            agent_id: None,
            env: BTreeMap::from([("CUSTOM_VAR".to_string(), "value".to_string())]),
            command_override: None,
            binary_path_override: None,
        };
        let env = merged_service_env(&spec);
        assert!(env.contains_key("CUSTOM_VAR"));
        assert_eq!(env.get("CUSTOM_VAR").map(String::as_str), Some("value"));
    }

    #[test]
    fn command_args_includes_listen_and_policy_config() {
        let spec = GatewayServiceInstallSpec {
            name: "test".to_string(),
            listen: "127.0.0.1:3000".to_string(),
            upstream: Some("https://api.example.com".to_string()),
            policy_configs: vec![
                PathBuf::from("config-a.yaml"),
                PathBuf::from("config-b.yaml"),
            ],
            fail_mode: "allow".to_string(),
            max_concurrency: Some(100),
            connected_mode: false,
            api_token: None,
            agent_id: None,
            env: BTreeMap::new(),
            command_override: None,
            binary_path_override: None,
        };
        let args: Vec<String> = command_args(&spec).unwrap().collect();
        assert!(args.contains(&"--listen".to_string()));
        assert!(args.contains(&"127.0.0.1:3000".to_string()));
        assert!(args.contains(&"--policy-config".to_string()));
    }

    #[test]
    fn service_file_path_launchd_contains_label() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = TestEnvGuard::new(&[(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        )]);
        let path = service_file_path(&ServicePlatform::Launchd, "my-gw").expect("path");
        assert!(path
            .to_string_lossy()
            .contains("com.verdictan.gateway.my-gw"));
        assert!(path.to_string_lossy().ends_with(".plist"));
    }

    #[test]
    fn service_file_path_systemd_contains_service_ext() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = TestEnvGuard::new(&[(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        )]);
        let path = service_file_path(&ServicePlatform::SystemdUser, "my-gw").expect("path");
        assert!(path.to_string_lossy().ends_with(".service"));
    }

    #[test]
    fn parse_launchctl_pid_zero_returns_none() {
        assert_eq!(parse_launchctl_pid("pid = 0\n"), None);
    }

    #[test]
    fn parse_launchctl_pid_missing_returns_none() {
        assert_eq!(parse_launchctl_pid("state = running\n"), None);
    }

    #[test]
    fn parse_key_value_extracts_correct_value() {
        assert_eq!(
            parse_key_value("Key1=Val1\nKey2=Val2\n", "Key2").as_deref(),
            Some("Val2")
        );
    }

    #[test]
    fn parse_key_value_missing_key() {
        assert_eq!(parse_key_value("Key1=Val1\n", "Key3"), None);
    }
}

#[cfg(test)]
mod coverage_expansion_gateway_service_tests {
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
    use super::tests::{sample_spec, TestEnvGuard};
    use super::*;

    // ── ServicePlatform ─────────────────────────────────────────────────

    #[test]
    fn service_platform_eq() {
        assert_eq!(ServicePlatform::Launchd, ServicePlatform::Launchd);
        assert_eq!(ServicePlatform::SystemdUser, ServicePlatform::SystemdUser);
        assert_ne!(ServicePlatform::Launchd, ServicePlatform::SystemdUser);
    }

    // ── GatewayServiceInstallSpec ───────────────────────────────────────

    #[test]
    fn gateway_service_install_spec_basic() {
        let spec = GatewayServiceInstallSpec {
            name: "verdictan-gateway".to_string(),
            listen: "0.0.0.0:41002".to_string(),
            upstream: Some("https://api.openai.com".to_string()),
            policy_configs: vec![],
            fail_mode: "block".to_string(),
            max_concurrency: Some(32),
            connected_mode: false,
            api_token: None,
            agent_id: None,
            env: BTreeMap::new(),
            command_override: None,
            binary_path_override: None,
        };
        assert_eq!(spec.name, "verdictan-gateway");
        assert_eq!(spec.listen, "0.0.0.0:41002");
    }

    // ── merged_service_env ──────────────────────────────────────────────

    #[test]
    fn merged_service_env_empty() {
        let spec = GatewayServiceInstallSpec {
            name: "test".to_string(),
            listen: "0.0.0.0:41002".to_string(),
            upstream: None,
            policy_configs: vec![],
            fail_mode: "block".to_string(),
            max_concurrency: None,
            connected_mode: false,
            api_token: None,
            agent_id: None,
            env: BTreeMap::new(),
            command_override: None,
            binary_path_override: None,
        };
        let env = merged_service_env(&spec);
        assert!(env.is_empty());
    }

    #[test]
    fn merged_service_env_with_agent_and_token() {
        let spec = GatewayServiceInstallSpec {
            name: "test".to_string(),
            listen: "0.0.0.0:41002".to_string(),
            upstream: None,
            policy_configs: vec![],
            fail_mode: "block".to_string(),
            max_concurrency: None,
            connected_mode: true,
            api_token: Some("my-token".to_string()),
            agent_id: Some("agent-123".to_string()),
            env: BTreeMap::new(),
            command_override: None,
            binary_path_override: None,
        };
        let env = merged_service_env(&spec);
        assert_eq!(
            env.get("VERDICTAN_API_TOKEN"),
            Some(&"my-token".to_string())
        );
        assert_eq!(
            env.get("VERDICTAN_AGENT_ID"),
            Some(&"agent-123".to_string())
        );
    }

    #[test]
    fn merged_service_env_empty_agent_not_inserted() {
        let spec = GatewayServiceInstallSpec {
            name: "test".to_string(),
            listen: "0.0.0.0:41002".to_string(),
            upstream: None,
            policy_configs: vec![],
            fail_mode: "block".to_string(),
            max_concurrency: None,
            connected_mode: false,
            api_token: Some("  ".to_string()),
            agent_id: Some("  ".to_string()),
            env: BTreeMap::new(),
            command_override: None,
            binary_path_override: None,
        };
        let env = merged_service_env(&spec);
        assert!(!env.contains_key("VERDICTAN_AGENT_ID"));
        assert!(!env.contains_key("VERDICTAN_API_TOKEN"));
    }

    #[test]
    fn merged_service_env_preserves_existing() {
        let mut base_env = BTreeMap::new();
        base_env.insert("CUSTOM_VAR".to_string(), "value".to_string());
        let spec = GatewayServiceInstallSpec {
            name: "test".to_string(),
            listen: "0.0.0.0:41002".to_string(),
            upstream: None,
            policy_configs: vec![],
            fail_mode: "block".to_string(),
            max_concurrency: None,
            connected_mode: false,
            api_token: Some("token".to_string()),
            agent_id: None,
            env: base_env,
            command_override: None,
            binary_path_override: None,
        };
        let env = merged_service_env(&spec);
        assert_eq!(env.get("CUSTOM_VAR"), Some(&"value".to_string()));
        assert_eq!(env.get("VERDICTAN_API_TOKEN"), Some(&"token".to_string()));
    }

    // ── ServiceStatus ───────────────────────────────────────────────────

    #[test]
    fn service_status_basic() {
        let status = ServiceStatus {
            platform: ServicePlatform::SystemdUser,
            label: "verdictan-gateway".to_string(),
            state: "active".to_string(),
            pid: Some(12345),
            service_file: PathBuf::from(
                "/home/user/.config/systemd/user/verdictan-gateway.service",
            ),
        };
        assert_eq!(status.platform, ServicePlatform::SystemdUser);
        assert_eq!(status.state, "active");
        assert_eq!(status.pid, Some(12345));
    }

    // ── Scope selection ────────────────────────────

    #[test]
    fn resolve_platform_picks_system_scope_only_for_a_privileged_process() {
        assert_eq!(
            resolve_platform("linux", true).expect("linux root"),
            ServicePlatform::SystemdSystem
        );
        assert_eq!(
            resolve_platform("linux", false).expect("linux user"),
            ServicePlatform::SystemdUser
        );
        assert_eq!(
            resolve_platform("macos", true).expect("macos root"),
            ServicePlatform::LaunchDaemon
        );
        assert_eq!(
            resolve_platform("macos", false).expect("macos user"),
            ServicePlatform::Launchd
        );
    }

    #[test]
    fn resolve_platform_supports_windows_and_rejects_an_unknown_os() {
        assert_eq!(
            resolve_platform("windows", false).expect("windows"),
            ServicePlatform::WindowsService
        );

        let err = resolve_platform("redox", true).expect_err("unknown os");
        assert!(err
            .to_string()
            .contains("service management is not supported on redox"));
    }

    #[test]
    fn candidate_platforms_lets_a_privileged_process_find_a_user_scope_install() {
        assert_eq!(
            candidate_platforms("linux", true),
            vec![ServicePlatform::SystemdSystem, ServicePlatform::SystemdUser]
        );
        assert_eq!(
            candidate_platforms("macos", true),
            vec![ServicePlatform::LaunchDaemon, ServicePlatform::Launchd]
        );
    }

    #[test]
    fn service_scope_and_display_name_match_the_platform() {
        for (platform, scope, name) in [
            (ServicePlatform::Launchd, ServiceScope::User, "launchd"),
            (
                ServicePlatform::LaunchDaemon,
                ServiceScope::System,
                "launchd (system)",
            ),
            (
                ServicePlatform::SystemdUser,
                ServiceScope::User,
                "systemd --user",
            ),
            (
                ServicePlatform::SystemdSystem,
                ServiceScope::System,
                "systemd (system)",
            ),
            (
                ServicePlatform::WindowsService,
                ServiceScope::System,
                "windows service",
            ),
        ] {
            assert_eq!(platform.scope(), scope, "scope for {name}");
            assert_eq!(platform.display_name(), name);
        }
    }

    // ── Path resolution ──────────────────

    #[test]
    fn service_file_path_resolves_each_system_scope_location() {
        assert_eq!(
            service_file_path(&ServicePlatform::SystemdSystem, "finance main").expect("unit path"),
            PathBuf::from("/etc/systemd/system/finance-main.service")
        );
        assert_eq!(
            service_file_path(&ServicePlatform::LaunchDaemon, "finance main").expect("daemon path"),
            PathBuf::from("/Library/LaunchDaemons/com.verdictan.gateway.finance-main.plist")
        );
        assert_eq!(
            service_file_path(&ServicePlatform::WindowsService, "finance main")
                .expect("registry key"),
            PathBuf::from(r"HKLM\SYSTEM\CurrentControlSet\Services").join("finance-main")
        );
    }

    #[test]
    fn service_file_path_rejects_a_name_with_no_usable_character() {
        let err = service_file_path(&ServicePlatform::SystemdSystem, "///")
            .expect_err("empty sanitized name");
        assert!(err
            .to_string()
            .contains("must contain at least one valid character"));
    }

    #[test]
    fn environment_file_path_uses_the_system_config_dir_for_a_system_unit() {
        assert_eq!(
            environment_file_path(&ServicePlatform::SystemdSystem, "finance-main")
                .expect("system env file"),
            PathBuf::from(SYSTEM_CONFIG_DIR).join("finance-main.env")
        );
    }

    #[test]
    fn environment_file_path_rejects_a_platform_with_no_environment_file() {
        for platform in [
            ServicePlatform::Launchd,
            ServicePlatform::LaunchDaemon,
            ServicePlatform::WindowsService,
        ] {
            let err =
                environment_file_path(&platform, "finance-main").expect_err("no environment file");
            assert!(err.to_string().contains("has no environment file"));
        }
    }

    #[test]
    fn logs_dir_keeps_a_launch_daemon_out_of_a_login_home() {
        assert_eq!(
            logs_dir(&ServicePlatform::LaunchDaemon).expect("daemon logs"),
            PathBuf::from("/var/log/verdictan")
        );
    }

    #[test]
    fn service_working_directory_is_the_root_for_a_system_scope_service() {
        assert_eq!(
            service_working_directory(&ServicePlatform::SystemdSystem).expect("system cwd"),
            PathBuf::from("/")
        );
        assert_eq!(
            service_working_directory(&ServicePlatform::LaunchDaemon).expect("daemon cwd"),
            PathBuf::from("/")
        );
    }

    // ── Install plan ─────────────────────

    #[test]
    fn build_install_plan_for_a_system_unit_creates_the_config_dir_and_service_user() {
        let plan = build_install_plan(&ServicePlatform::SystemdSystem, &sample_spec())
            .expect("system install plan");

        assert_eq!(plan.service_user.as_deref(), Some(SYSTEM_SERVICE_USER));
        assert!(plan
            .directories
            .contains(&PathBuf::from(SYSTEMD_SYSTEM_UNIT_DIR)));
        assert!(
            plan.directories.contains(&PathBuf::from(SYSTEM_CONFIG_DIR)),
            "the plan must create {SYSTEM_CONFIG_DIR}: {:?}",
            plan.directories
        );
        assert_eq!(
            plan.service_file,
            PathBuf::from("/etc/systemd/system/finance-main.service")
        );
    }

    #[test]
    fn build_install_plan_puts_the_token_in_a_private_environment_file_only() {
        let plan = build_install_plan(&ServicePlatform::SystemdSystem, &sample_spec())
            .expect("system install plan");

        let env_file = plan
            .files
            .iter()
            .find(|file| file.path.ends_with("finance-main.env"))
            .expect("environment file write");
        assert!(env_file.private, "the environment file must be owner only");
        assert!(env_file.contents.contains("VERDICTAN_API_TOKEN="));

        let unit = plan
            .files
            .iter()
            .find(|file| file.path.ends_with("finance-main.service"))
            .expect("unit write");
        assert!(
            !unit.private,
            "a unit that references an environment file embeds no secret"
        );
        assert!(!unit.contents.contains("service-token"));
    }

    #[test]
    fn build_install_plan_marks_a_launchd_plist_private_because_it_inlines_the_token() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let _env = TestEnvGuard::new(&[(
            "VERDICTAN_TEST_HOME",
            dir.path().to_string_lossy().to_string(),
        )]);

        let plan = build_install_plan(&ServicePlatform::Launchd, &sample_spec())
            .expect("launchd install plan");

        let plist = plan
            .files
            .iter()
            .find(|file| file.path.extension().is_some_and(|ext| ext == "plist"))
            .expect("plist write");
        assert!(
            plist.private,
            "launchd has no environment file, so the plist itself must be owner only"
        );
        assert!(plist.contents.contains("service-token"));
        assert!(plan.service_user.is_none());
    }

    #[test]
    fn build_install_plan_rejects_a_windows_unit_file() {
        let err = build_install_plan(&ServicePlatform::WindowsService, &sample_spec())
            .expect_err("windows has no unit file");
        assert!(err.to_string().contains("does not use a unit file"));
    }

    // ── Activation ───────────────────────────────────────────

    #[test]
    fn activation_commands_enable_linger_for_a_user_scope_systemd_unit() {
        let commands = activation_commands(
            &ServicePlatform::SystemdUser,
            "finance-main",
            Path::new("/ignored"),
        )
        .expect("user activation");

        let rendered = commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            vec![
                "systemctl --user daemon-reload".to_string(),
                "loginctl enable-linger".to_string(),
                "systemctl --user enable --now finance-main.service".to_string(),
            ]
        );
    }

    #[test]
    fn activation_commands_for_a_system_unit_use_the_system_manager_and_no_linger() {
        let commands = activation_commands(
            &ServicePlatform::SystemdSystem,
            "finance-main",
            Path::new("/ignored"),
        )
        .expect("system activation");

        let rendered = commands
            .iter()
            .map(|command| format!("{} {}", command.program, command.args.join(" ")))
            .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            vec![
                "systemctl daemon-reload".to_string(),
                "systemctl enable --now finance-main.service".to_string(),
            ]
        );
        assert!(!rendered.iter().any(|command| command.contains("--user")));
    }

    #[test]
    fn deactivation_commands_are_scope_aware_and_never_strict() {
        let user = deactivation_commands(&ServicePlatform::SystemdUser, "finance-main")
            .expect("user deactivation");
        assert_eq!(
            user[0].args,
            vec!["--user", "disable", "--now", "finance-main.service"]
        );
        assert!(!user[0].strict);

        let system = deactivation_commands(&ServicePlatform::SystemdSystem, "finance-main")
            .expect("system deactivation");
        assert_eq!(
            system[0].args,
            vec!["disable", "--now", "finance-main.service"]
        );
        assert!(!system[0].strict);
    }

    // ── Active-state verification ────────────────────────────

    #[test]
    fn interpret_active_state_reports_the_observed_systemd_state() {
        assert_eq!(
            interpret_active_state(&ServicePlatform::SystemdSystem, true, "active\n"),
            Ok("active".to_string())
        );
        assert_eq!(
            interpret_active_state(&ServicePlatform::SystemdSystem, false, "failed\n"),
            Err("failed".to_string())
        );
        assert_eq!(
            interpret_active_state(&ServicePlatform::SystemdUser, false, "   "),
            Err("unknown".to_string())
        );
    }

    #[test]
    fn interpret_active_state_separates_a_loaded_launchd_job_from_a_running_one() {
        assert_eq!(
            interpret_active_state(
                &ServicePlatform::LaunchDaemon,
                true,
                "  state = running\n  pid = 42\n"
            ),
            Ok("running".to_string())
        );
        assert_eq!(
            interpret_active_state(&ServicePlatform::LaunchDaemon, true, "  state = waiting\n"),
            Err("loaded".to_string())
        );
        assert_eq!(
            interpret_active_state(&ServicePlatform::Launchd, false, ""),
            Err("not_loaded".to_string())
        );
    }

    #[test]
    fn interpret_active_state_reads_the_windows_service_state() {
        assert_eq!(
            interpret_active_state(
                &ServicePlatform::WindowsService,
                true,
                "        STATE              : 4  RUNNING\n"
            ),
            Ok("RUNNING".to_string())
        );
        assert_eq!(
            interpret_active_state(
                &ServicePlatform::WindowsService,
                true,
                "        STATE              : 1  STOPPED\n"
            ),
            Err("STOPPED".to_string())
        );
        assert_eq!(
            interpret_active_state(&ServicePlatform::WindowsService, false, "no state here"),
            Err("unknown".to_string())
        );
    }

    // ── Windows backend ──────────────────────────────────────

    #[test]
    fn parse_sc_query_state_reads_the_word_after_the_numeric_code() {
        assert_eq!(
            parse_sc_query_state("        STATE              : 4  RUNNING\n").as_deref(),
            Some("RUNNING")
        );
        assert_eq!(parse_sc_query_state("SERVICE_NAME: finance-main\n"), None);
    }

    #[test]
    fn windows_quote_only_quotes_a_value_with_whitespace() {
        assert_eq!(windows_quote("gateway"), "gateway");
        assert_eq!(
            windows_quote(r"C:\Program Files\verdictan.exe"),
            "\"C:\\Program Files\\verdictan.exe\""
        );
    }

    #[test]
    fn windows_service_bin_path_quotes_the_executable_and_arguments() {
        let mut spec = sample_spec();
        spec.binary_path_override = Some(PathBuf::from(r"C:\Program Files\verdictan.exe"));
        spec.policy_configs = vec![];
        spec.command_override = Some(vec!["gateway".to_string(), "run".to_string()]);

        let bin_path = windows_service_bin_path(&spec).expect("bin path");
        assert!(bin_path.starts_with('"'), "unexpected bin path: {bin_path}");
        assert!(bin_path.ends_with("gateway run"));
    }

    #[test]
    fn render_windows_service_environment_block_joins_entries_with_a_newline() {
        let env = BTreeMap::from([
            ("VERDICTAN_API_TOKEN".to_string(), "tok".to_string()),
            (
                "VERDICTAN_API_URL".to_string(),
                "https://api.test".to_string(),
            ),
        ]);

        assert_eq!(
            render_windows_service_environment_block(&env).expect("env block"),
            "VERDICTAN_API_TOKEN=tok\nVERDICTAN_API_URL=https://api.test"
        );
    }

    #[test]
    fn render_windows_service_environment_block_rejects_a_control_character() {
        let env = BTreeMap::from([(
            "VERDICTAN_API_TOKEN".to_string(),
            "tok\nVERDICTAN_API_URL=https://evil.test".to_string(),
        )]);

        let err = render_windows_service_environment_block(&env)
            .expect_err("a newline would inject a second entry");
        assert!(err
            .to_string()
            .contains("unsupported control characters for windows"));
    }
}
