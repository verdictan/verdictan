// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use chrono::Utc;
use clap::Args;

use crate::error::CliError;
use crate::instances::status::{ConfigVerificationState, GatewayInstanceLifecycle};
use crate::instances::GatewayInstanceStatus;
use crate::output::json::print_json;
use crate::supervisor::{
    default_state_dir, OperationAction, OperationHistoryEntry, OperationOutcome,
    SupervisorStateStore,
};

#[derive(Clone, Debug)]
pub(crate) struct ParsedGatewayConfig {
    pub(crate) version: Option<String>,
    pub(crate) sha256: Option<String>,
    pub(crate) content: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct GatewayReloadArgs {
    #[arg(long)]
    pub(crate) name: String,

    #[arg(long)]
    pub(crate) gateway_url: String,

    #[arg(long)]
    pub(crate) config_path: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) json: bool,
}
pub(crate) async fn run_async(args: GatewayReloadArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.unwrap_or(default_state_dir()?);
    let mut store = SupervisorStateStore::load(&state_dir)?;
    let record = store
        .get_instance(&args.name)
        .cloned()
        .ok_or_else(|| CliError::user(format!("instance {} does not exist", args.name)))?;

    let config_paths = args.config_path.map_or_else(
        || {
            record
                .spec
                .policy_config_source
                .path_values()
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect::<Vec<_>>()
        },
        |path| vec![path],
    );
    if config_paths.is_empty() {
        return Err(CliError::user(
            "instance has no policy config path; pass --config-path",
        ));
    }

    let loaded =
        crate::gateway::declarative_config::LoadedDeclarativeConfig::from_paths(&config_paths)?;
    let config_yaml = loaded.raw_yaml.clone();
    let config_source = describe_config_paths(&config_paths);

    let api_token = resolve_gateway_api_token(
        None,
        record
            .spec
            .admin_token
            .as_ref()
            .and_then(|secret_ref| secret_ref.resolve()),
    );
    let before = fetch_gateway_config(&args.gateway_url, api_token.as_deref()).await?;

    let mut instance_status: GatewayInstanceStatus = record.status;
    instance_status.lifecycle = GatewayInstanceLifecycle::Starting;
    instance_status.desired_config_version = Some(loaded.config_version.clone());
    instance_status.desired_config_sha256 = Some(loaded.config_sha256.clone());
    instance_status.desired_config_source = Some(config_source.clone());
    instance_status.rollback_target_version = before.version.clone();
    instance_status.rollback_target_sha256 = before.sha256.clone();
    instance_status.rollback_target_yaml = before.content.clone();
    instance_status.last_reload_reason = Some(format!("reload requested from {config_source}"));
    instance_status.last_rollback_reason = None;
    instance_status.verification_state = ConfigVerificationState::Pending;
    instance_status.last_verified_at = None;
    instance_status.updated_at = Utc::now().to_rfc3339();
    store.set_status(&args.name, instance_status.clone())?;

    let value =
        post_reload_gateway_config(&args.gateway_url, &config_yaml, api_token.as_deref()).await?;
    let reloaded = parse_reload_config(&value)?;

    let verify_result = async {
        let verified = verify_gateway_config(
            &args.gateway_url,
            api_token.as_deref(),
            &loaded.config_sha256,
            &loaded.config_version,
        )
        .await?;
        verify_gateway_health(&args.gateway_url).await?;
        Ok::<_, CliError>(verified)
    }
    .await;

    match verify_result {
        Ok(verified) => {
            instance_status.lifecycle = GatewayInstanceLifecycle::Running;
            instance_status.observed_config_version =
                verified.version.clone().or(reloaded.version.clone());
            instance_status.observed_config_sha256 =
                verified.sha256.clone().or(reloaded.sha256.clone());
            instance_status.last_known_good_version =
                instance_status.observed_config_version.clone();
            instance_status.last_known_good_sha256 = instance_status.observed_config_sha256.clone();
            instance_status.last_error = None;
            instance_status.verification_state = ConfigVerificationState::Verified;
            instance_status.last_verified_at = Some(Utc::now().to_rfc3339());
            instance_status.last_healthcheck_at = Some(Utc::now().to_rfc3339());
            instance_status.last_observed_healthy = Some(true);
            instance_status.last_seen_at = Some(Utc::now().to_rfc3339());
            instance_status.updated_at = Utc::now().to_rfc3339();
            store.set_status(&args.name, instance_status)?;
            store.append_operation_history(
                &args.name,
                OperationHistoryEntry {
                    action: OperationAction::Reload,
                    outcome: OperationOutcome::Succeeded,
                    reason: None,
                    previous_version: before.version.clone(),
                    previous_sha256: before.sha256.clone(),
                    target_version: Some(loaded.config_version.clone()),
                    target_sha256: Some(loaded.config_sha256.clone()),
                    active_version: verified.version,
                    active_sha256: verified.sha256,
                    recorded_at: Utc::now().to_rfc3339(),
                },
            )?;

            if args.json {
                return print_json(&value);
            }

            if let Some(version) = reloaded.version.as_deref() {
                println!("reloaded {} to version {}", args.name, version);
            } else {
                println!("reloaded {}", args.name);
            }

            Ok(())
        }
        Err(verify_error) => {
            let rollback_result = if let Some(rollback_yaml) = before.content.as_deref() {
                post_reload_gateway_config(&args.gateway_url, rollback_yaml, api_token.as_deref())
                    .await
            } else {
                Err(CliError::internal(
                    "activation verification failed and no rollback target was available",
                ))
            };

            match rollback_result {
                Ok(_) => {
                    instance_status.lifecycle = GatewayInstanceLifecycle::Failed;
                    instance_status.observed_config_version = before.version.clone();
                    instance_status.observed_config_sha256 = before.sha256.clone();
                    instance_status.last_known_good_version = before.version.clone();
                    instance_status.last_known_good_sha256 = before.sha256.clone();
                    instance_status.last_rollback_reason = Some(verify_error.to_string());
                    instance_status.last_error = Some(format!(
                        "activation failed and rollback was applied: {}",
                        verify_error
                    ));
                    instance_status.verification_state = ConfigVerificationState::RolledBack;
                    instance_status.last_verified_at = Some(Utc::now().to_rfc3339());
                    instance_status.last_healthcheck_at = Some(Utc::now().to_rfc3339());
                    instance_status.last_observed_healthy = Some(false);
                    instance_status.last_seen_at = Some(Utc::now().to_rfc3339());
                    instance_status.updated_at = Utc::now().to_rfc3339();
                    store.set_status(&args.name, instance_status)?;
                    store.append_operation_history(
                        &args.name,
                        OperationHistoryEntry {
                            action: OperationAction::Reload,
                            outcome: OperationOutcome::RolledBack,
                            reason: Some(verify_error.to_string()),
                            previous_version: before.version.clone(),
                            previous_sha256: before.sha256.clone(),
                            target_version: Some(loaded.config_version.clone()),
                            target_sha256: Some(loaded.config_sha256.clone()),
                            active_version: before.version.clone(),
                            active_sha256: before.sha256.clone(),
                            recorded_at: Utc::now().to_rfc3339(),
                        },
                    )?;
                    Err(CliError::network(format!(
                        "proxy activation failed verification and rollback was applied: {}",
                        verify_error
                    )))
                }
                Err(rollback_error) => {
                    instance_status.lifecycle = GatewayInstanceLifecycle::Failed;
                    instance_status.last_error = Some(format!(
                        "activation verification failed: {}; rollback also failed: {}",
                        verify_error, rollback_error
                    ));
                    instance_status.verification_state = ConfigVerificationState::Failed;
                    instance_status.last_healthcheck_at = Some(Utc::now().to_rfc3339());
                    instance_status.last_observed_healthy = Some(false);
                    instance_status.last_seen_at = Some(Utc::now().to_rfc3339());
                    instance_status.updated_at = Utc::now().to_rfc3339();
                    store.set_status(&args.name, instance_status)?;
                    store.append_operation_history(
                        &args.name,
                        OperationHistoryEntry {
                            action: OperationAction::Reload,
                            outcome: OperationOutcome::Failed,
                            reason: Some(format!(
                                "activation verification failed: {}; rollback failed: {}",
                                verify_error, rollback_error
                            )),
                            previous_version: before.version.clone(),
                            previous_sha256: before.sha256.clone(),
                            target_version: Some(loaded.config_version.clone()),
                            target_sha256: Some(loaded.config_sha256.clone()),
                            active_version: reloaded.version.clone(),
                            active_sha256: reloaded.sha256.clone(),
                            recorded_at: Utc::now().to_rfc3339(),
                        },
                    )?;
                    Err(CliError::network(format!(
                        "proxy activation failed verification and rollback failed: {}; {}",
                        verify_error, rollback_error
                    )))
                }
            }
        }
    }
}

fn describe_config_paths(paths: &[std::path::PathBuf]) -> String {
    match paths {
        [path] => path.display().to_string(),
        _ => paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
    }
}

pub(crate) fn resolve_gateway_api_token(
    explicit_token: Option<String>,
    stored_token: Option<String>,
) -> Option<String> {
    explicit_token
        .or(stored_token)
        .or_else(|| std::env::var("VERDICTAN_API_TOKEN").ok())
        .filter(|value| !value.trim().is_empty())
}

pub(crate) async fn post_reload_gateway_config(
    gateway_url: &str,
    config_yaml: &str,
    api_token: Option<&str>,
) -> Result<serde_json::Value, CliError> {
    let url = format!(
        "{}/verdictan/config/reload",
        gateway_url.trim_end_matches('/')
    );
    let client =
        crate::gateway::http_client::shared_gateway_http_client().map_err(CliError::internal)?;
    let mut request = client
        .post(&url)
        .json(&serde_json::json!({ "config_yaml": config_yaml }));

    if let Some(token) = api_token {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .map_err(|e| CliError::network(format!("failed to reload proxy config: {e}")))?;
    let status = response.status();
    let body_text = response
        .text()
        .await
        .map_err(|e| CliError::network(format!("failed to read proxy response: {e}")))?;

    if !status.is_success() {
        return Err(CliError::network(format!(
            "proxy reload endpoint returned {}: {}",
            status, body_text
        )));
    }

    serde_json::from_str(&body_text)
        .map_err(|e| CliError::internal(format!("proxy reload response is not valid JSON: {e}")))
}

pub(crate) fn parse_reload_config(
    value: &serde_json::Value,
) -> Result<ParsedGatewayConfig, CliError> {
    let config = value
        .get("config")
        .and_then(|item| item.as_object())
        .ok_or_else(|| CliError::internal("proxy reload response missing config object"))?;

    Ok(ParsedGatewayConfig {
        version: config
            .get("config_version")
            .and_then(|item| item.as_str())
            .map(ToString::to_string),
        sha256: config
            .get("config_sha256")
            .and_then(|item| item.as_str())
            .map(ToString::to_string),
        content: config
            .get("config_content")
            .and_then(|item| item.as_str())
            .map(ToString::to_string),
    })
}

pub(crate) async fn fetch_gateway_config(
    gateway_url: &str,
    api_token: Option<&str>,
) -> Result<ParsedGatewayConfig, CliError> {
    let url = format!("{}/verdictan/config", gateway_url.trim_end_matches('/'));
    let client =
        crate::gateway::http_client::shared_gateway_http_client().map_err(CliError::internal)?;
    let mut request = client.get(&url);
    if let Some(token) = api_token {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .map_err(|e| CliError::network(format!("failed to query proxy config: {e}")))?;
    let status = response.status();
    let body_text = response
        .text()
        .await
        .map_err(|e| CliError::network(format!("failed to read proxy response: {e}")))?;

    if !status.is_success() {
        return Err(CliError::network(format!(
            "proxy config endpoint returned {}: {}",
            status, body_text
        )));
    }

    let value: serde_json::Value = serde_json::from_str(&body_text)
        .map_err(|e| CliError::internal(format!("proxy config response is not valid JSON: {e}")))?;
    parse_reload_config(&value)
}

pub(crate) async fn verify_gateway_config(
    gateway_url: &str,
    api_token: Option<&str>,
    expected_sha256: &str,
    expected_version: &str,
) -> Result<ParsedGatewayConfig, CliError> {
    let config = fetch_gateway_config(gateway_url, api_token).await?;
    let actual_sha = config.sha256.as_deref().unwrap_or_default();
    if actual_sha != expected_sha256 {
        return Err(CliError::network(format!(
            "expected active config digest {} but proxy is reporting {}",
            expected_sha256, actual_sha
        )));
    }

    let actual_version = config.version.as_deref().unwrap_or_default();
    if actual_version != expected_version {
        return Err(CliError::network(format!(
            "expected active config version {} but proxy is reporting {}",
            expected_version, actual_version
        )));
    }

    Ok(config)
}

pub(crate) async fn verify_gateway_health(gateway_url: &str) -> Result<(), CliError> {
    let url = format!("{}/healthz", gateway_url.trim_end_matches('/'));
    let client =
        crate::gateway::http_client::shared_gateway_http_client().map_err(CliError::internal)?;
    let response =
        client.get(&url).send().await.map_err(|error| {
            CliError::network(format!("failed to query gateway health: {error}"))
        })?;
    let status = response.status();
    let body_text = response
        .text()
        .await
        .map_err(|error| CliError::network(format!("failed to read gateway health: {error}")))?;

    if !status.is_success() {
        return Err(CliError::network(format!(
            "gateway health endpoint returned {status}: {body_text}"
        )));
    }

    let body: serde_json::Value = serde_json::from_str(&body_text).map_err(|error| {
        CliError::network(format!(
            "gateway health response is not valid JSON: {error}"
        ))
    })?;
    let actual = body
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if actual != "ok" {
        return Err(CliError::network(format!(
            "expected gateway health status ok but proxy is reporting {actual}"
        )));
    }

    Ok(())
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
        describe_config_paths, fetch_gateway_config, parse_reload_config,
        post_reload_gateway_config, resolve_gateway_api_token, run_async, verify_gateway_config,
        verify_gateway_health, GatewayReloadArgs,
    };
    use crate::instances::{GatewayInstanceId, GatewayInstanceSpec, PolicyConfigSource};
    use crate::supervisor::SupervisorStateStore;
    use axum::{
        extract::State,
        http::HeaderMap,
        routing::{get, post},
        Json, Router,
    };
    use serde::Deserialize;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct StubState {
        config: Arc<Mutex<serde_json::Value>>,
        auth_headers: Arc<Mutex<Vec<Option<String>>>>,
        reload_payloads: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Deserialize)]
    struct ReloadRequest {
        config_yaml: String,
    }

    async fn get_config(
        State(state): State<StubState>,
        headers: HeaderMap,
    ) -> Json<serde_json::Value> {
        state.auth_headers.lock().expect("auth headers").push(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
        );
        Json(state.config.lock().expect("config").clone())
    }

    async fn reload_config(
        State(state): State<StubState>,
        headers: HeaderMap,
        Json(body): Json<ReloadRequest>,
    ) -> Json<serde_json::Value> {
        state.auth_headers.lock().expect("auth headers").push(
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
        );
        state
            .reload_payloads
            .lock()
            .expect("payloads")
            .push(body.config_yaml);
        Json(state.config.lock().expect("config").clone())
    }

    async fn start_stub(
        initial_config: serde_json::Value,
    ) -> (String, StubState, tokio::task::JoinHandle<()>) {
        let state = StubState {
            config: Arc::new(Mutex::new(initial_config)),
            auth_headers: Arc::new(Mutex::new(Vec::new())),
            reload_payloads: Arc::new(Mutex::new(Vec::new())),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let app = Router::new()
            .route("/verdictan/config", get(get_config))
            .route("/verdictan/config/reload", post(reload_config))
            .route(
                "/healthz",
                get(|| async { Json(json!({ "status": "ok" })) }),
            )
            .with_state(state.clone());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve stub");
        });

        (format!("http://{addr}"), state, handle)
    }

    fn create_instance(state_dir: &std::path::Path, name: &str) {
        let spec = GatewayInstanceSpec::new(
            GatewayInstanceId::new(name).expect("instance id"),
            format!("{name}_gw"),
            name,
            "127.0.0.1:41002",
            "https://api.example.com",
            None,
            None,
            None,
            "block",
            PolicyConfigSource::Empty,
            8,
            None,
            true,
        )
        .expect("spec");
        let mut store = SupervisorStateStore::load(state_dir).expect("load store");
        store.create_instance(spec).expect("create instance");
    }

    #[test]
    fn describe_config_paths_formats_single_and_multiple_paths() {
        assert_eq!(
            describe_config_paths(&[std::path::PathBuf::from("/tmp/policy.yaml")]),
            "/tmp/policy.yaml"
        );
        assert_eq!(
            describe_config_paths(&[
                std::path::PathBuf::from("/tmp/base.yaml"),
                std::path::PathBuf::from("/tmp/overlay.yaml")
            ]),
            "/tmp/base.yaml, /tmp/overlay.yaml"
        );
    }

    #[test]
    fn resolve_gateway_api_token_uses_explicit_then_stored_then_env() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        crate::test_support::set_var("VERDICTAN_API_TOKEN", "env-token");

        assert_eq!(
            resolve_gateway_api_token(Some("explicit".to_string()), Some("stored".to_string()))
                .as_deref(),
            Some("explicit")
        );
        assert_eq!(
            resolve_gateway_api_token(None, Some("stored".to_string())).as_deref(),
            Some("stored")
        );
        assert_eq!(
            resolve_gateway_api_token(None, None).as_deref(),
            Some("env-token")
        );

        crate::test_support::unset_var("VERDICTAN_API_TOKEN");
    }

    #[test]
    fn parse_reload_config_requires_config_object() {
        let parsed = parse_reload_config(&json!({
            "config": {
                "config_version": "2.0.0",
                "config_sha256": "sha-256",
                "config_content": "pack: {}"
            }
        }))
        .expect("parse config");
        assert_eq!(parsed.version.as_deref(), Some("2.0.0"));
        assert_eq!(parsed.sha256.as_deref(), Some("sha-256"));
        assert_eq!(parsed.content.as_deref(), Some("pack: {}"));

        let error = parse_reload_config(&json!({ "missing": {} })).expect_err("missing config");
        assert!(error.to_string().contains("missing config object"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_post_and_verify_gateway_config_use_expected_routes() {
        let (base_url, state, handle) = start_stub(json!({
            "config": {
                "config_version": "4.0.0",
                "config_sha256": "sha-live",
                "config_content": "pack:\n  version: \"4.0.0\"\n"
            }
        }))
        .await;

        let fetched = fetch_gateway_config(&format!("{base_url}/"), Some("secret-token"))
            .await
            .expect("fetch config");
        assert_eq!(fetched.version.as_deref(), Some("4.0.0"));

        let posted = post_reload_gateway_config(
            &format!("{base_url}/"),
            "pack:\n  version: \"4.0.0\"\n",
            Some("secret-token"),
        )
        .await
        .expect("post reload");
        assert_eq!(posted["config"]["config_sha256"].as_str(), Some("sha-live"));

        let verified = verify_gateway_config(&base_url, Some("secret-token"), "sha-live", "4.0.0")
            .await
            .expect("verify config");
        assert_eq!(verified.sha256.as_deref(), Some("sha-live"));
        verify_gateway_health(&base_url)
            .await
            .expect("verify health");

        let auth_headers = state.auth_headers.lock().expect("auth headers").clone();
        assert!(auth_headers
            .iter()
            .all(|item| item.as_deref() == Some("Bearer secret-token")));
        let payloads = state.reload_payloads.lock().expect("payloads").clone();
        assert_eq!(payloads, vec!["pack:\n  version: \"4.0.0\"\n".to_string()]);

        handle.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_async_requires_config_path_when_instance_has_no_saved_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        create_instance(&state_dir, "reload_main");

        let error = run_async(GatewayReloadArgs {
            name: "reload_main".to_string(),
            gateway_url: "http://127.0.0.1:41002".to_string(),
            config_path: None,
            state_dir: Some(state_dir),
            json: false,
        })
        .await
        .expect_err("missing config path");

        assert!(error.to_string().contains("pass --config-path"));
    }

    #[test]
    fn describe_config_paths_empty_slice() {
        assert_eq!(describe_config_paths(&[]), "");
    }

    #[test]
    fn resolve_gateway_api_token_all_none_and_no_env() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        crate::test_support::unset_var("VERDICTAN_API_TOKEN");
        assert_eq!(resolve_gateway_api_token(None, None), None);
    }

    #[test]
    fn parse_reload_config_extracts_all_fields() {
        let parsed = parse_reload_config(&json!({
            "config": {
                "config_version": "5.0.0",
                "config_sha256": "sha-abc",
                "config_content": "pack:\n  name: test"
            }
        }))
        .expect("parse config");
        assert_eq!(parsed.version.as_deref(), Some("5.0.0"));
        assert_eq!(parsed.sha256.as_deref(), Some("sha-abc"));
        assert_eq!(parsed.content.as_deref(), Some("pack:\n  name: test"));
    }

    #[test]
    fn parse_reload_config_missing_optional_fields() {
        let parsed = parse_reload_config(&json!({
            "config": {}
        }))
        .expect("parse minimal config");
        assert_eq!(parsed.version, None);
        assert_eq!(parsed.sha256, None);
        assert_eq!(parsed.content, None);
    }

    #[test]
    fn args_debug_impl() {
        let args = GatewayReloadArgs {
            name: "my-gw".to_string(),
            gateway_url: "http://localhost:8080".to_string(),
            config_path: Some(std::path::PathBuf::from("/tmp/policy.yaml")),
            state_dir: None,
            json: true,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("my-gw"));
        assert!(debug.contains("localhost"));
    }
}
