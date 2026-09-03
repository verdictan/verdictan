// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;
use crate::supervisor::{default_state_dir, SupervisorStateStore};

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) api_url: Option<String>,

    #[arg(long, default_value = "default")]
    pub(crate) profile: String,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(serde::Serialize)]
struct CheckResult {
    name: String,
    status: CheckStatus,
    message: String,
}

#[derive(Debug, serde::Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CheckStatus {
    Ok,
    Warn,
    Fail,
}
pub(crate) async fn run_async(args: DoctorArgs) -> Result<(), CliError> {
    let mut checks: Vec<CheckResult> = Vec::new();

    // 1. API connectivity
    checks.push(check_api_connectivity(&args).await);

    // 2. Config file existence and validity
    checks.push(check_config_file(&args));

    // 3. State directory permissions
    checks.push(check_state_dir(&args));

    // 4. Proxy process liveness
    checks.push(check_proxy_liveness(&args));

    if args.json {
        return print_json(&checks);
    }

    let mut has_failure = false;
    for check in &checks {
        let icon = match check.status {
            CheckStatus::Ok => "✓",
            CheckStatus::Warn => "!",
            CheckStatus::Fail => "✗",
        };
        println!("  {} {}: {}", icon, check.name, check.message);
        if check.status == CheckStatus::Fail {
            has_failure = true;
        }
    }

    if has_failure {
        println!("\nSome checks failed. Review the output above.");
        return Err(CliError::user("one or more required checks failed"));
    }

    println!("\nAll checks passed.");
    Ok(())
}

async fn check_api_connectivity(args: &DoctorArgs) -> CheckResult {
    let inputs = ConfigInputs {
        api_url_flag: args.api_url.clone(),
        api_token_flag: None,
        config_path: args.config.clone(),
        profile_flag: Some(args.profile.clone()),
        region_flag: None,
    };

    let config = match Config::resolve(inputs) {
        Ok(c) => c,
        Err(e) => {
            return CheckResult {
                name: "api_connectivity".to_string(),
                status: CheckStatus::Fail,
                message: format!("failed to resolve config: {e}"),
            };
        }
    };

    let api_token = match config.api_token {
        Some(t) => t,
        None => {
            return CheckResult {
                name: "api_connectivity".to_string(),
                status: CheckStatus::Warn,
                message: "no API token configured; skipping connectivity check".to_string(),
            };
        }
    };

    let client = match AsyncApiClient::new(config.api_url.clone(), api_token) {
        Ok(c) => c,
        Err(e) => {
            return CheckResult {
                name: "api_connectivity".to_string(),
                status: CheckStatus::Fail,
                message: format!("failed to create API client: {e}"),
            };
        }
    };

    match client.get_json_value("/v1/health").await {
        Ok(_) => CheckResult {
            name: "api_connectivity".to_string(),
            status: CheckStatus::Ok,
            message: format!("API reachable at {}", config.api_url),
        },
        Err(e) => CheckResult {
            name: "api_connectivity".to_string(),
            status: CheckStatus::Fail,
            message: format!("API unreachable at {}: {e}", config.api_url),
        },
    }
}

fn check_config_file(args: &DoctorArgs) -> CheckResult {
    let path = args
        .config
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("policy-config.yaml"));

    if !path.exists() {
        return CheckResult {
            name: "config_file".to_string(),
            status: CheckStatus::Warn,
            message: format!("config file not found at {}", path.display()),
        };
    }

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            return CheckResult {
                name: "config_file".to_string(),
                status: CheckStatus::Fail,
                message: format!("cannot read {}: {e}", path.display()),
            };
        }
    };

    match serde_yaml::from_slice::<serde_yaml::Value>(&bytes) {
        Ok(_) => CheckResult {
            name: "config_file".to_string(),
            status: CheckStatus::Ok,
            message: format!("valid YAML at {}", path.display()),
        },
        Err(e) => CheckResult {
            name: "config_file".to_string(),
            status: CheckStatus::Fail,
            message: format!("invalid YAML at {}: {e}", path.display()),
        },
    }
}

fn check_state_dir(args: &DoctorArgs) -> CheckResult {
    let state_dir = match args.state_dir.clone().or_else(|| default_state_dir().ok()) {
        Some(d) => d,
        None => {
            return CheckResult {
                name: "state_directory".to_string(),
                status: CheckStatus::Warn,
                message: "unable to determine state directory (HOME not set)".to_string(),
            };
        }
    };

    if !state_dir.exists() {
        return CheckResult {
            name: "state_directory".to_string(),
            status: CheckStatus::Warn,
            message: format!("state directory does not exist: {}", state_dir.display()),
        };
    }

    let metadata = match std::fs::metadata(&state_dir) {
        Ok(m) => m,
        Err(e) => {
            return CheckResult {
                name: "state_directory".to_string(),
                status: CheckStatus::Fail,
                message: format!("cannot stat {}: {e}", state_dir.display()),
            };
        }
    };

    if !metadata.is_dir() {
        return CheckResult {
            name: "state_directory".to_string(),
            status: CheckStatus::Fail,
            message: format!("{} exists but is not a directory", state_dir.display()),
        };
    }

    // Try to create a temp file to test write permissions.
    let test_path = state_dir.join(".doctor-probe");
    match std::fs::write(&test_path, b"probe") {
        Ok(()) => {
            let _ = std::fs::remove_file(&test_path);
            CheckResult {
                name: "state_directory".to_string(),
                status: CheckStatus::Ok,
                message: format!("state directory writable at {}", state_dir.display()),
            }
        }
        Err(e) => CheckResult {
            name: "state_directory".to_string(),
            status: CheckStatus::Fail,
            message: format!(
                "state directory not writable at {}: {e}",
                state_dir.display()
            ),
        },
    }
}

fn check_proxy_liveness(args: &DoctorArgs) -> CheckResult {
    let state_dir = match args.state_dir.clone().or_else(|| default_state_dir().ok()) {
        Some(d) => d,
        None => {
            return CheckResult {
                name: "proxy_liveness".to_string(),
                status: CheckStatus::Warn,
                message: "unable to determine state directory".to_string(),
            };
        }
    };

    let store = match SupervisorStateStore::load(&state_dir) {
        Ok(s) => s,
        Err(_) => {
            return CheckResult {
                name: "proxy_liveness".to_string(),
                status: CheckStatus::Warn,
                message: "no supervisor state found".to_string(),
            };
        }
    };

    let instances = store.list_instances();
    if instances.is_empty() {
        return CheckResult {
            name: "proxy_liveness".to_string(),
            status: CheckStatus::Warn,
            message: "no proxy instances registered".to_string(),
        };
    }

    let running = instances
        .iter()
        .filter(|i| i.lifecycle == "running")
        .count();
    let total = instances.len();

    CheckResult {
        name: "proxy_liveness".to_string(),
        status: if running > 0 {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        message: format!("{running}/{total} proxy instances running"),
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
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::thread::JoinHandle;

    use tempfile::{tempdir, TempDir};

    use crate::config::test_env_lock;
    use crate::instances::status::GatewayInstanceLifecycle;
    use crate::instances::PolicyConfigSource;
    use crate::instances::{GatewayInstanceId, GatewayInstanceSpec, GatewayInstanceStatus};
    use crate::supervisor::state_store::STATE_FILE_NAME;
    use crate::test_support::{set_var, unset_var};

    struct EnvGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvGuard {
        fn capture(keys: &[&'static str]) -> Self {
            Self {
                saved: keys
                    .iter()
                    .map(|key| (*key, std::env::var_os(key)))
                    .collect(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                match value {
                    Some(value) => set_var(key, value),
                    None => unset_var(key),
                }
            }
        }
    }

    fn doctor_args() -> DoctorArgs {
        DoctorArgs {
            config: None,
            api_url: None,
            profile: "default".to_string(),
            state_dir: None,
            json: false,
        }
    }

    fn write_config(dir: &TempDir, contents: &str) -> PathBuf {
        let path = dir.path().join("policy-config.yaml");
        std::fs::write(&path, contents).expect("write config");
        path
    }

    fn instance_spec(instance_id: &str) -> GatewayInstanceSpec {
        GatewayInstanceSpec::new(
            GatewayInstanceId::new(instance_id).expect("instance id"),
            format!("gateway_{instance_id}"),
            format!("instance_{instance_id}"),
            "127.0.0.1:8080",
            "https://example.com",
            None,
            None,
            None,
            "allow",
            PolicyConfigSource::path("policy-config.yaml"),
            1,
            None,
            true,
        )
        .expect("instance spec")
    }

    fn write_instance(state_dir: &Path, instance_id: &str, lifecycle: GatewayInstanceLifecycle) {
        let mut store = SupervisorStateStore::load(state_dir.to_path_buf()).expect("load store");
        store
            .create_instance(instance_spec(instance_id))
            .expect("create instance");
        store
            .set_status(
                instance_id,
                GatewayInstanceStatus::default().with_lifecycle(lifecycle),
            )
            .expect("set status");
    }

    fn spawn_health_server() -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind health server");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept health request");
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer);

            let body = r#"{"status":"ok"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("write response");
        });

        (format!("http://{addr}"), handle)
    }

    fn unused_local_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        format!("http://{addr}")
    }

    #[test]
    fn check_config_file_warns_when_missing() {
        let temp = tempdir().expect("tempdir");
        let args = DoctorArgs {
            config: Some(temp.path().join("missing.yaml")),
            ..doctor_args()
        };

        let result = check_config_file(&args);

        assert_eq!(result.name, "config_file");
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.message.contains("config file not found"));
    }

    #[test]
    fn check_config_file_fails_when_path_is_directory() {
        let temp = tempdir().expect("tempdir");
        let args = DoctorArgs {
            config: Some(temp.path().to_path_buf()),
            ..doctor_args()
        };

        let result = check_config_file(&args);

        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("cannot read"));
    }

    #[test]
    fn check_config_file_accepts_valid_yaml() {
        let temp = tempdir().expect("tempdir");
        let config_path = write_config(&temp, "version: 1\n");
        let args = DoctorArgs {
            config: Some(config_path.clone()),
            ..doctor_args()
        };

        let result = check_config_file(&args);

        assert_eq!(result.status, CheckStatus::Ok);
        assert_eq!(
            result.message,
            format!("valid YAML at {}", config_path.display())
        );
    }

    #[test]
    fn check_config_file_rejects_invalid_yaml() {
        let temp = tempdir().expect("tempdir");
        let config_path = write_config(&temp, "foo: [\n");
        let args = DoctorArgs {
            config: Some(config_path.clone()),
            ..doctor_args()
        };

        let result = check_config_file(&args);

        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("invalid YAML"));
        assert!(result.message.contains(&config_path.display().to_string()));
    }

    #[test]
    fn check_state_dir_warns_when_home_is_unset() {
        let _env_lock = test_env_lock().lock().expect("env lock");
        let _env_guard = EnvGuard::capture(&["HOME"]);
        unset_var("HOME");

        let result = check_state_dir(&doctor_args());

        assert_eq!(result.name, "state_directory");
        assert_eq!(result.status, CheckStatus::Warn);
        assert_eq!(
            result.message,
            "unable to determine state directory (HOME not set)"
        );
    }

    #[test]
    fn check_state_dir_warns_when_directory_is_missing() {
        let temp = tempdir().expect("tempdir");
        let args = DoctorArgs {
            state_dir: Some(temp.path().join("missing")),
            ..doctor_args()
        };

        let result = check_state_dir(&args);

        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.message.contains("state directory does not exist"));
    }

    #[test]
    fn check_state_dir_fails_when_path_is_file() {
        let temp = tempdir().expect("tempdir");
        let file_path = temp.path().join("state-file");
        std::fs::write(&file_path, "not a directory").expect("write file");
        let args = DoctorArgs {
            state_dir: Some(file_path.clone()),
            ..doctor_args()
        };

        let result = check_state_dir(&args);

        assert_eq!(result.status, CheckStatus::Fail);
        assert_eq!(
            result.message,
            format!("{} exists but is not a directory", file_path.display())
        );
    }

    #[test]
    fn check_state_dir_reports_writable_directory_and_cleans_probe() {
        let temp = tempdir().expect("tempdir");
        let args = DoctorArgs {
            state_dir: Some(temp.path().to_path_buf()),
            ..doctor_args()
        };

        let result = check_state_dir(&args);

        assert_eq!(result.status, CheckStatus::Ok);
        assert_eq!(
            result.message,
            format!("state directory writable at {}", temp.path().display())
        );
        assert!(!temp.path().join(".doctor-probe").exists());
    }

    #[test]
    fn check_proxy_liveness_warns_when_home_is_unset() {
        let _env_lock = test_env_lock().lock().expect("env lock");
        let _env_guard = EnvGuard::capture(&["HOME"]);
        unset_var("HOME");

        let result = check_proxy_liveness(&doctor_args());

        assert_eq!(result.name, "proxy_liveness");
        assert_eq!(result.status, CheckStatus::Warn);
        assert_eq!(result.message, "unable to determine state directory");
    }

    #[test]
    fn check_proxy_liveness_warns_when_supervisor_state_is_invalid() {
        let temp = tempdir().expect("tempdir");
        std::fs::write(temp.path().join(STATE_FILE_NAME), "{not-json").expect("write state");
        let args = DoctorArgs {
            state_dir: Some(temp.path().to_path_buf()),
            ..doctor_args()
        };

        let result = check_proxy_liveness(&args);

        assert_eq!(result.status, CheckStatus::Warn);
        assert_eq!(result.message, "no supervisor state found");
    }

    #[test]
    fn check_proxy_liveness_warns_when_no_instances_are_registered() {
        let temp = tempdir().expect("tempdir");
        let args = DoctorArgs {
            state_dir: Some(temp.path().to_path_buf()),
            ..doctor_args()
        };

        let result = check_proxy_liveness(&args);

        assert_eq!(result.status, CheckStatus::Warn);
        assert_eq!(result.message, "no proxy instances registered");
    }

    #[test]
    fn check_proxy_liveness_warns_when_no_instances_are_running() {
        let temp = tempdir().expect("tempdir");
        write_instance(temp.path(), "alpha", GatewayInstanceLifecycle::Stopped);
        let args = DoctorArgs {
            state_dir: Some(temp.path().to_path_buf()),
            ..doctor_args()
        };

        let result = check_proxy_liveness(&args);

        assert_eq!(result.status, CheckStatus::Warn);
        assert_eq!(result.message, "0/1 proxy instances running");
    }

    #[test]
    fn check_proxy_liveness_reports_running_instances() {
        let temp = tempdir().expect("tempdir");
        write_instance(temp.path(), "alpha", GatewayInstanceLifecycle::Running);
        write_instance(temp.path(), "beta", GatewayInstanceLifecycle::Stopped);
        let args = DoctorArgs {
            state_dir: Some(temp.path().to_path_buf()),
            ..doctor_args()
        };

        let result = check_proxy_liveness(&args);

        assert_eq!(result.status, CheckStatus::Ok);
        assert_eq!(result.message, "1/2 proxy instances running");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn check_api_connectivity_fails_when_config_cannot_be_resolved() {
        let temp = tempdir().expect("tempdir");
        let config_path = write_config(&temp, "api_url: [\n");
        let args = DoctorArgs {
            config: Some(config_path),
            ..doctor_args()
        };

        let result = check_api_connectivity(&args).await;

        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("failed to resolve config"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn check_api_connectivity_warns_when_no_token_is_configured() {
        let _env_lock = test_env_lock().lock().expect("env lock");
        let _env_guard = EnvGuard::capture(&["HOME", "VERDICTAN_API_TOKEN", "VERDICTAN_CONFIG"]);
        let temp = tempdir().expect("tempdir");
        let config_path = write_config(&temp, "profile: default\n");
        set_var("HOME", temp.path());
        unset_var("VERDICTAN_API_TOKEN");
        unset_var("VERDICTAN_CONFIG");

        let args = DoctorArgs {
            config: Some(config_path),
            api_url: Some("http://127.0.0.1:1".to_string()),
            ..doctor_args()
        };

        let result = check_api_connectivity(&args).await;

        assert_eq!(result.status, CheckStatus::Warn);
        assert_eq!(
            result.message,
            "no API token configured; skipping connectivity check"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn check_api_connectivity_fails_when_client_cannot_be_created() {
        let temp = tempdir().expect("tempdir");
        let config_path = write_config(&temp, "profile: default\n");
        set_var("VERDICTAN_API_TOKEN", "token");
        let args = DoctorArgs {
            config: Some(config_path),
            api_url: Some("   ".to_string()),
            ..doctor_args()
        };

        let result = check_api_connectivity(&args).await;

        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("failed to create API client"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn check_api_connectivity_fails_when_api_is_unreachable() {
        let temp = tempdir().expect("tempdir");
        let config_path = write_config(&temp, "profile: default\n");
        let api_url = unused_local_url();
        set_var("VERDICTAN_API_TOKEN", "token");
        let args = DoctorArgs {
            config: Some(config_path),
            api_url: Some(api_url.clone()),
            ..doctor_args()
        };

        let result = check_api_connectivity(&args).await;

        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.message.contains("API unreachable"));
        assert!(result.message.contains(&api_url));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn check_api_connectivity_reports_reachable_api() {
        let temp = tempdir().expect("tempdir");
        let config_path = write_config(&temp, "profile: default\n");
        let (api_url, handle) = spawn_health_server();
        set_var("VERDICTAN_API_TOKEN", "token");
        let args = DoctorArgs {
            config: Some(config_path),
            api_url: Some(api_url.clone()),
            ..doctor_args()
        };

        let result = check_api_connectivity(&args).await;
        handle.join().expect("join server");

        assert_eq!(result.status, CheckStatus::Ok);
        assert_eq!(result.message, format!("API reachable at {api_url}"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_async_returns_json_output_when_requested() {
        let temp = tempdir().expect("tempdir");
        let config_path = write_config(&temp, "version: 1\n");
        write_instance(temp.path(), "alpha", GatewayInstanceLifecycle::Running);
        let (api_url, handle) = spawn_health_server();
        set_var("VERDICTAN_API_TOKEN", "token");
        let args = DoctorArgs {
            config: Some(config_path),
            api_url: Some(api_url),
            profile: "default".to_string(),
            state_dir: Some(temp.path().to_path_buf()),
            json: true,
        };

        let result = run_async(args).await;
        handle.join().expect("join server");

        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_async_prints_success_summary_when_all_checks_pass() {
        let temp = tempdir().expect("tempdir");
        let config_path = write_config(&temp, "version: 1\n");
        write_instance(temp.path(), "alpha", GatewayInstanceLifecycle::Running);
        let (api_url, handle) = spawn_health_server();
        set_var("VERDICTAN_API_TOKEN", "token");
        let args = DoctorArgs {
            config: Some(config_path),
            api_url: Some(api_url),
            profile: "default".to_string(),
            state_dir: Some(temp.path().to_path_buf()),
            json: false,
        };

        let result = run_async(args).await;
        handle.join().expect("join server");

        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_async_returns_error_when_any_check_fails() {
        let temp = tempdir().expect("tempdir");
        set_var("VERDICTAN_API_TOKEN", "token");
        let args = DoctorArgs {
            config: Some(temp.path().join("missing-config.yaml")),
            api_url: Some(unused_local_url()),
            profile: "default".to_string(),
            state_dir: Some(temp.path().join("missing-state")),
            json: false,
        };

        let result = run_async(args).await;

        assert!(result.is_err());
    }
}
