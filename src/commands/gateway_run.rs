// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::error::CliError;
use crate::runtime::RuntimeInstanceConfig;

pub const DYNAMIC_PROVIDER_UPSTREAM_SENTINEL: &str = "http://verdictan-dynamic-provider.invalid";
pub const DEFAULT_HOSTED_UPSTREAM_URL: &str = "https://api.verdictan.com";
pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:41002";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GatewayRunEnvironment {
    pub api_base_url: Option<String>,
    pub api_token: Option<String>,
    pub upstream_url: Option<String>,
    pub upstream_api_key: Option<String>,
    pub upstream_api_key_header: Option<String>,
    pub upstream_api_key_prefix: Option<String>,
    pub max_concurrency: Option<usize>,
    pub runtime_registration_id: Option<String>,
    pub runtime_agent_id: Option<String>,
    pub runtime_agent_selector: Option<String>,
}

impl GatewayRunEnvironment {
    pub fn from_process() -> Self {
        Self {
            api_base_url: read_trimmed_non_empty_env("VERDICTAN_API_URL"),
            api_token: read_trimmed_non_empty_env("VERDICTAN_API_TOKEN"),
            upstream_url: read_env("VERDICTAN_UPSTREAM_URL"),
            upstream_api_key: read_env("VERDICTAN_UPSTREAM_API_KEY"),
            upstream_api_key_header: read_env("VERDICTAN_UPSTREAM_API_KEY_HEADER"),
            upstream_api_key_prefix: read_env("VERDICTAN_UPSTREAM_API_KEY_PREFIX"),
            max_concurrency: read_env("VERDICTAN_GATEWAY_MAX_CONCURRENCY")
                .and_then(|value| value.parse::<usize>().ok()),
            runtime_registration_id: read_trimmed_non_empty_env(
                "VERDICTAN_RUNTIME_REGISTRATION_ID",
            ),
            runtime_agent_id: read_trimmed_non_empty_env("VERDICTAN_AGENT_ID"),
            runtime_agent_selector: read_trimmed_non_empty_env("VERDICTAN_AGENT_NAME"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GatewayRuntimeLaunchEnv {
    pub api_token: Option<String>,
    pub agent_id: Option<String>,
}

impl GatewayRuntimeLaunchEnv {
    pub fn apply_to_process_env(&self) {
        if let Some(api_token) = self.api_token.as_deref() {
            std::env::set_var("VERDICTAN_API_TOKEN", api_token);
        }
        if let Some(agent_id) = self.agent_id.as_deref() {
            std::env::set_var("VERDICTAN_AGENT_ID", agent_id);
        }
    }
}

#[derive(Debug, Args)]
pub struct GatewayRunArgs {
    /// Listen address (host:port)
    #[arg(long, default_value = DEFAULT_LISTEN_ADDR)]
    pub listen: String,

    /// Upstream base URL (for example, https://api.openai.com)
    #[arg(long)]
    pub upstream: Option<String>,

    /// Header name for the upstream API key from VERDICTAN_UPSTREAM_API_KEY.
    /// Defaults to Authorization.
    #[arg(long)]
    pub upstream_api_key_header: Option<String>,

    /// Prefix added before upstream API key value. Defaults to "Bearer ". Use empty for raw key headers.
    #[arg(long)]
    pub upstream_api_key_prefix: Option<String>,

    /// Fail mode when upstream is down.
    #[arg(long, default_value = "block", value_parser = ["allow", "block"]) ]
    pub fail_mode: String,

    /// Declarative config files (YAML) for baseline enforcement.
    /// Subsequent files overlay previous files. Set --agent to bind the config.
    #[arg(long)]
    pub policy_config: Vec<std::path::PathBuf>,

    /// Agent name for the gateway policy config. Set this when you use --policy-config.
    /// If the control plane has no matching agent, the CLI creates it.
    /// For a configured agent and config combination, the CLI creates a new version.
    /// Then, it rolls the version to the fleet. Without --policy-config, this value
    /// selects a configured agent by name or ID for runtime binding.
    #[arg(long)]
    pub agent: Option<String>,

    /// Configuration name used when syncing local policy to the control plane. Defaults to the
    /// stem of the first --policy-config filename.
    #[arg(long)]
    pub config_name: Option<String>,

    /// Maximum concurrent upstream requests before adaptive backoff kicks in.
    #[arg(long)]
    pub max_concurrency: Option<usize>,

    /// Durable runtime registration ID issued by the control plane for connected gateways.
    #[arg(long = "runtime-registration-id")]
    pub runtime_registration_id: Option<String>,
}

pub(crate) fn resolve_policy_config_paths(
    explicit_paths: &[std::path::PathBuf],
    connected_mode: bool,
    default_path: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    if !explicit_paths.is_empty() {
        return explicit_paths.to_vec();
    }

    if connected_mode || !default_path.exists() {
        return Vec::new();
    }

    vec![default_path.to_path_buf()]
}

pub fn build_runtime_config(
    args: GatewayRunArgs,
    event_sink: Option<crate::gateway::server::EventSinkConfig>,
) -> Result<RuntimeInstanceConfig, CliError> {
    build_runtime_config_with_env(args, event_sink, &GatewayRunEnvironment::from_process())
}

pub fn build_runtime_config_with_env(
    args: GatewayRunArgs,
    event_sink: Option<crate::gateway::server::EventSinkConfig>,
    env: &GatewayRunEnvironment,
) -> Result<RuntimeInstanceConfig, CliError> {
    build_runtime_config_with_env_connected_mode(
        args,
        event_sink,
        env,
        crate::gateway::gateway_env::gateway_control_plane_connected(),
    )
}

fn build_runtime_config_with_env_connected_mode(
    args: GatewayRunArgs,
    event_sink: Option<crate::gateway::server::EventSinkConfig>,
    env: &GatewayRunEnvironment,
    connected_mode: bool,
) -> Result<RuntimeInstanceConfig, CliError> {
    let listen = crate::gateway::request_id::parse_listen_addr(&args.listen)?;
    let fail_mode = crate::gateway::fail_mode::FailMode::parse(&args.fail_mode)
        .ok_or_else(|| CliError::user("invalid --fail-mode (expected allow|block)"))?;

    // When local policy configs are explicitly provided via CLI, they MUST be bound to an agent.
    // Connected gateways no longer auto-load /etc/verdictan/policy-config.yaml because they
    // wait for an API deployment instead of serving a baked-in local fallback.
    if !args.policy_config.is_empty() && args.agent.is_none() {
        return Err(CliError::user(
            "--policy-config requires --agent <name> to bind the configuration to an agent. \
             Every local policy must be tied to an agent for enforcement to be effective.",
        ));
    }

    let upstream = args
        .upstream
        .or_else(|| env.upstream_url.clone())
        .unwrap_or_else(|| {
            if connected_mode {
                DYNAMIC_PROVIDER_UPSTREAM_SENTINEL.to_string()
            } else {
                DEFAULT_HOSTED_UPSTREAM_URL.to_string()
            }
        });

    let upstream_auth = env.upstream_api_key.clone().map(|key| {
        let header_name = args
            .upstream_api_key_header
            .clone()
            .or_else(|| env.upstream_api_key_header.clone())
            .unwrap_or_else(|| "Authorization".to_string());

        let key_prefix = args
            .upstream_api_key_prefix
            .clone()
            .or_else(|| env.upstream_api_key_prefix.clone())
            .unwrap_or_else(|| "Bearer ".to_string());

        crate::gateway::server::UpstreamAuthConfig {
            header_name,
            header_value: format!("{key_prefix}{key}"),
        }
    });

    let config_paths = resolve_policy_config_paths(
        &args.policy_config,
        connected_mode,
        std::path::Path::new("/etc/verdictan/policy-config.yaml"),
    );
    let loaded_config =
        crate::gateway::declarative_config::LoadedDeclarativeConfig::from_paths(&config_paths)?;

    let max_concurrency = args
        .max_concurrency
        .or(env.max_concurrency)
        .unwrap_or(16)
        .max(1);

    let mut config = RuntimeInstanceConfig::new(
        None,
        listen,
        upstream,
        upstream_auth,
        fail_mode,
        loaded_config,
        max_concurrency,
        true,
        event_sink,
    );
    config.source_config_path = match config_paths.as_slice() {
        [path] => Some(path.display().to_string()),
        _ => None,
    };
    config.connected_mode = connected_mode;
    config.runtime_registration_id = args
        .runtime_registration_id
        .or_else(|| env.runtime_registration_id.clone())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    Ok(config)
}

pub fn resolve_runtime_launch_env(
    env: &GatewayRunEnvironment,
    event_sink: Option<&crate::gateway::server::EventSinkConfig>,
    resolved_agent_id: Option<&str>,
) -> GatewayRuntimeLaunchEnv {
    let api_token = if env
        .api_token
        .as_ref()
        .and_then(|value| trimmed_non_empty(value.clone()))
        .is_some()
    {
        None
    } else {
        event_sink.and_then(|config| trimmed_non_empty(config.api_token.clone()))
    };

    let agent_id = if env
        .runtime_agent_id
        .as_ref()
        .and_then(|value| trimmed_non_empty(value.clone()))
        .is_some()
    {
        None
    } else {
        resolved_agent_id.and_then(|value| trimmed_non_empty(value.to_string()))
    };

    GatewayRuntimeLaunchEnv {
        api_token,
        agent_id,
    }
}

fn trimmed_non_empty(value: impl Into<String>) -> Option<String> {
    let value = value.into();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else if trimmed.len() == value.len() {
        Some(value)
    } else {
        Some(trimmed.to_string())
    }
}

fn read_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn read_trimmed_non_empty_env(name: &str) -> Option<String> {
    read_env(name).and_then(trimmed_non_empty)
}

fn resolve_api_base_url(env: &GatewayRunEnvironment) -> String {
    env.api_base_url
        .clone()
        .unwrap_or_else(|| DEFAULT_HOSTED_UPSTREAM_URL.to_string())
}

pub fn resolve_event_sink_config(
    _args: &GatewayRunArgs,
    env: &GatewayRunEnvironment,
    api_base_url: &str,
) -> Option<crate::gateway::server::EventSinkConfig> {
    env.api_token
        .clone()
        .and_then(trimmed_non_empty)
        .map(|api_token| crate::gateway::server::EventSinkConfig {
            base_url: api_base_url.to_string(),
            api_token: api_token.clone(),
            gateway_service_token: Some(api_token),
        })
}

fn configured_runtime_agent_selector(
    args: &GatewayRunArgs,
    env: &GatewayRunEnvironment,
) -> Option<String> {
    args.agent.clone().and_then(trimmed_non_empty).or_else(|| {
        env.runtime_agent_selector
            .as_ref()
            .and_then(|value| trimmed_non_empty(value.clone()))
    })
}

fn agent_text(agent: &serde_json::Value, field: &str) -> Option<String> {
    agent
        .get(field)
        .and_then(|value| value.as_str())
        .and_then(trimmed_non_empty)
}

fn find_agent_id_by_selector(
    agents: &[serde_json::Value],
    selector: &str,
) -> Result<Option<String>, CliError> {
    let Some(selector) = trimmed_non_empty(selector.to_string()) else {
        return Ok(None);
    };

    for agent in agents {
        if ["id", "agent_id"]
            .iter()
            .filter_map(|field| agent_text(agent, field))
            .any(|value| value == selector)
        {
            return Ok(agent_text(agent, "id").or_else(|| agent_text(agent, "agent_id")));
        }
    }

    let mut matches = agents
        .iter()
        .filter(|agent| {
            ["name", "display_name", "resource_name"]
                .iter()
                .filter_map(|field| agent_text(agent, field))
                .any(|value| value == selector)
        })
        .filter_map(|agent| agent_text(agent, "id").or_else(|| agent_text(agent, "agent_id")))
        .collect::<Vec<_>>();

    matches.sort();
    matches.dedup();

    match matches.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(id.clone())),
        _ => Err(CliError::user(format!(
            "agent name '{selector}' matched multiple agents; set VERDICTAN_AGENT_ID to the exact agent ID."
        ))),
    }
}

async fn resolve_existing_agent_id(
    api_base_url: &str,
    api_token: &str,
    selector: &str,
) -> Result<String, CliError> {
    let client = crate::api::AsyncApiClient::new(api_base_url, api_token)?;
    let list = client.get_json_value("/v1/agents").await?;
    let agents = list
        .get("agents")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    find_agent_id_by_selector(&agents, selector)?.ok_or_else(|| {
        CliError::user(format!(
            "agent '{selector}' was not found on the control plane. Use an existing agent name or set VERDICTAN_AGENT_ID to the agent ID."
        ))
    })
}

pub fn run(args: GatewayRunArgs) -> Result<(), CliError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::internal(format!("failed to build tokio runtime: {e}")))?;
    rt.block_on(run_async(args))
}

pub(crate) async fn run_async(args: GatewayRunArgs) -> Result<(), CliError> {
    let launch_env = GatewayRunEnvironment::from_process();
    let api_base_url = resolve_api_base_url(&launch_env);
    let event_sink = resolve_event_sink_config(&args, &launch_env, &api_base_url);

    if event_sink.is_none() {
        tracing::warn!(
            api_url = %api_base_url,
            "no API token provided — gateway telemetry and history writeback disabled. \
             Set VERDICTAN_API_TOKEN to connect."
        );
    }

    let mut resolved_agent_id = None;

    if let Some(ref agent_name) = args.agent {
        if !args.policy_config.is_empty() {
            let api_token = event_sink
                .as_ref()
                .map(|s| s.api_token.clone())
                .ok_or_else(|| {
                    CliError::user(
                        "--agent requires an API token to sync with the control plane. \
                         Set VERDICTAN_API_TOKEN.",
                    )
                })?;

            let config_name = args.config_name.clone().unwrap_or_else(|| {
                args.policy_config
                    .first()
                    .and_then(|p| p.file_stem())
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "default".to_string())
            });

            resolved_agent_id = Some(
                ensure_agent_config(
                    &api_base_url,
                    &api_token,
                    agent_name,
                    &config_name,
                    &args.policy_config,
                )
                .await?,
            );
        }
    }

    if resolved_agent_id.is_none() && launch_env.runtime_agent_id.is_none() {
        if let Some(agent_selector) = configured_runtime_agent_selector(&args, &launch_env) {
            let api_token = event_sink
                .as_ref()
                .map(|s| s.api_token.clone())
                .ok_or_else(|| {
                    CliError::user(
                        "--agent or VERDICTAN_AGENT_NAME requires an API token to resolve the agent. \
                         Set VERDICTAN_API_TOKEN.",
                    )
                })?;
            resolved_agent_id =
                Some(resolve_existing_agent_id(&api_base_url, &api_token, &agent_selector).await?);
        }
    }

    let runtime_config = build_runtime_config_with_env(args, event_sink.clone(), &launch_env)?;
    resolve_runtime_launch_env(
        &launch_env,
        event_sink.as_ref(),
        resolved_agent_id.as_deref(),
    )
    .apply_to_process_env();
    crate::telemetry::init(true)?;
    runtime_config.run_until_ctrl_c().await
}

/// Create or update an agent and configuration on the control plane.
///
/// - If there is no agent with `agent_name`, create it.
/// - If there is no configuration with `config_name`, create it and save the first version.
/// - If the configuration is available, save a new version with the supplied YAML content.
///
/// This makes `verdictan gateway run --agent <name> --policy-config <file>` a single command that
/// creates or updates all parts of the agent, config, and fleet binding.
async fn ensure_agent_config(
    api_base_url: &str,
    api_token: &str,
    agent_name: &str,
    config_name: &str,
    policy_paths: &[std::path::PathBuf],
) -> Result<String, CliError> {
    let client = crate::api::AsyncApiClient::new(api_base_url, api_token)?;

    // ── 1. Ensure agent exists (by name) ─────────────────────────────────────
    let agent_id = ensure_agent(&client, agent_name).await?;
    tracing::info!(agent_id = %agent_id, agent_name = %agent_name, "agent ready");

    // ── 2. Read and merge policy config YAML ─────────────────────────────────
    let mut merged_yaml = String::new();
    for path in policy_paths {
        let content = std::fs::read_to_string(path).map_err(|e| {
            CliError::user(format!(
                "failed to read policy config {}: {e}",
                path.display()
            ))
        })?;
        if !merged_yaml.is_empty() {
            merged_yaml.push_str("\n---\n");
        }
        merged_yaml.push_str(&content);
    }

    // ── 3. Ensure configuration exists and save version ──────────────────────
    let config_id = ensure_configuration(&client, config_name, &agent_id).await?;
    save_configuration_version(&client, &config_id, &merged_yaml).await?;
    tracing::info!(
        config_id = %config_id,
        config_name = %config_name,
        agent_id = %agent_id,
        "configuration version saved and rolled to agent fleet"
    );

    Ok(agent_id)
}

async fn ensure_agent(
    client: &crate::api::AsyncApiClient,
    agent_name: &str,
) -> Result<String, CliError> {
    // List agents and find by name.
    let list = client.get_json_value("/v1/agents").await?;
    let agents = list
        .get("agents")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for agent in &agents {
        let name = agent.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name == agent_name {
            let id = agent
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            return Ok(id);
        }
    }

    // Agent not found — create it.
    let body = serde_json::json!({ "name": agent_name });
    let result = client.post_json_value("/v1/agents", &body).await?;
    let id = result
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CliError::internal("agent creation response missing id"))?
        .to_string();
    tracing::info!(agent_id = %id, "created agent '{agent_name}'");
    Ok(id)
}

async fn ensure_configuration(
    client: &crate::api::AsyncApiClient,
    config_name: &str,
    agent_id: &str,
) -> Result<String, CliError> {
    // List configurations and find by name.
    let list = client.get_json_value("/v1/configurations").await?;
    let configs = list
        .get("configurations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for config in &configs {
        let name = config.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name == config_name {
            let id = config
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            return Ok(id);
        }
    }

    // Configuration not found — create it and bind to the agent.
    let body = serde_json::json!({
        "name": config_name,
        "agent_id": agent_id,
    });
    let result = client.post_json_value("/v1/configurations", &body).await?;
    let id = result
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CliError::internal("configuration creation response missing id"))?
        .to_string();
    tracing::info!(config_id = %id, "created configuration '{config_name}'");
    Ok(id)
}

async fn save_configuration_version(
    client: &crate::api::AsyncApiClient,
    config_id: &str,
    yaml_content: &str,
) -> Result<(), CliError> {
    let path = format!("/v1/configurations/{config_id}/versions");
    let body = serde_json::json!({
        "yaml": yaml_content,
        "deploy": true,
    });
    client.post_json_value(&path, &body).await?;
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
        build_runtime_config, build_runtime_config_with_env,
        build_runtime_config_with_env_connected_mode, configured_runtime_agent_selector,
        ensure_agent_config, find_agent_id_by_selector, resolve_api_base_url,
        resolve_event_sink_config, resolve_policy_config_paths, resolve_runtime_launch_env, run,
        run_async, trimmed_non_empty, GatewayRunArgs, GatewayRunEnvironment,
        GatewayRuntimeLaunchEnv, DEFAULT_HOSTED_UPSTREAM_URL, DEFAULT_LISTEN_ADDR,
        DYNAMIC_PROVIDER_UPSTREAM_SENTINEL,
    };
    use axum::{
        extract::{Path as AxumPath, State},
        http::HeaderMap,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug, PartialEq)]
    struct RecordedRequest {
        method: &'static str,
        path: String,
        authorization: Option<String>,
        body: Option<serde_json::Value>,
    }

    #[derive(Clone)]
    struct MockControlPlaneState {
        agents_response: Arc<Mutex<serde_json::Value>>,
        create_agent_response: Arc<Mutex<serde_json::Value>>,
        configurations_response: Arc<Mutex<serde_json::Value>>,
        create_configuration_response: Arc<Mutex<serde_json::Value>>,
        save_configuration_version_response: Arc<Mutex<serde_json::Value>>,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
    }

    impl Default for MockControlPlaneState {
        fn default() -> Self {
            Self {
                agents_response: Arc::new(Mutex::new(json!({ "agents": [] }))),
                create_agent_response: Arc::new(Mutex::new(json!({ "id": "agent-created" }))),
                configurations_response: Arc::new(Mutex::new(json!({ "configurations": [] }))),
                create_configuration_response: Arc::new(Mutex::new(json!({
                    "id": "config-created"
                }))),
                save_configuration_version_response: Arc::new(Mutex::new(json!({
                    "saved": true
                }))),
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl MockControlPlaneState {
        fn record(
            &self,
            method: &'static str,
            path: String,
            headers: &HeaderMap,
            body: Option<serde_json::Value>,
        ) {
            self.requests
                .lock()
                .expect("requests lock")
                .push(RecordedRequest {
                    method,
                    path,
                    authorization: headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .map(|value| value.to_string()),
                    body,
                });
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().expect("requests lock").clone()
        }
    }

    const GATEWAY_RUN_TEST_ENV_KEYS: &[&str] = &[
        "VERDICTAN_API_URL",
        "VERDICTAN_API_TOKEN",
        "VERDICTAN_UPSTREAM_URL",
        "VERDICTAN_UPSTREAM_API_KEY",
        "VERDICTAN_UPSTREAM_API_KEY_HEADER",
        "VERDICTAN_UPSTREAM_API_KEY_PREFIX",
        "VERDICTAN_GATEWAY_MAX_CONCURRENCY",
        "VERDICTAN_RUNTIME_REGISTRATION_ID",
        "VERDICTAN_AGENT_ID",
        "VERDICTAN_AGENT_NAME",
        "VERDICTAN_AGENT_NAME",
        "VERDICTAN_ENV",
        "VERDICTAN_DEPLOYMENT_MODE",
    ];

    struct GatewayRunEnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl Drop for GatewayRunEnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                if let Some(value) = value {
                    crate::test_support::set_var(key, value);
                } else {
                    crate::test_support::unset_var(key);
                }
            }
        }
    }

    struct MockControlPlaneServer {
        base_url: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl MockControlPlaneServer {
        fn url(&self) -> &str {
            &self.base_url
        }
    }

    impl Drop for MockControlPlaneServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn list_agents_handler(
        State(state): State<MockControlPlaneState>,
        headers: HeaderMap,
    ) -> Json<serde_json::Value> {
        state.record("GET", "/v1/agents".to_string(), &headers, None);
        Json(
            state
                .agents_response
                .lock()
                .expect("agents response lock")
                .clone(),
        )
    }

    async fn create_agent_handler(
        State(state): State<MockControlPlaneState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        state.record("POST", "/v1/agents".to_string(), &headers, Some(body));
        Json(
            state
                .create_agent_response
                .lock()
                .expect("create agent response lock")
                .clone(),
        )
    }

    async fn list_configurations_handler(
        State(state): State<MockControlPlaneState>,
        headers: HeaderMap,
    ) -> Json<serde_json::Value> {
        state.record("GET", "/v1/configurations".to_string(), &headers, None);
        Json(
            state
                .configurations_response
                .lock()
                .expect("configurations response lock")
                .clone(),
        )
    }

    async fn create_configuration_handler(
        State(state): State<MockControlPlaneState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        state.record(
            "POST",
            "/v1/configurations".to_string(),
            &headers,
            Some(body),
        );
        Json(
            state
                .create_configuration_response
                .lock()
                .expect("create configuration response lock")
                .clone(),
        )
    }

    async fn save_configuration_version_handler(
        AxumPath(config_id): AxumPath<String>,
        State(state): State<MockControlPlaneState>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        state.record(
            "POST",
            format!("/v1/configurations/{config_id}/versions"),
            &headers,
            Some(body),
        );
        Json(
            state
                .save_configuration_version_response
                .lock()
                .expect("save configuration version response lock")
                .clone(),
        )
    }

    async fn spawn_mock_control_plane(state: MockControlPlaneState) -> MockControlPlaneServer {
        let app = Router::new()
            .route(
                "/v1/agents",
                get(list_agents_handler).post(create_agent_handler),
            )
            .route(
                "/v1/configurations",
                get(list_configurations_handler).post(create_configuration_handler),
            )
            .route(
                "/v1/configurations/:config_id/versions",
                post(save_configuration_version_handler),
            )
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock control plane");
        let addr = listener.local_addr().expect("mock control plane addr");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock control plane");
        });

        MockControlPlaneServer {
            base_url: format!("http://{addr}"),
            task,
        }
    }

    fn reset_gateway_run_env() -> GatewayRunEnvGuard {
        let saved = GATEWAY_RUN_TEST_ENV_KEYS
            .iter()
            .map(|key| {
                let saved = std::env::var_os(key);
                crate::test_support::unset_var(key);
                (*key, saved)
            })
            .collect();

        GatewayRunEnvGuard { saved }
    }

    fn gateway_run_args() -> GatewayRunArgs {
        GatewayRunArgs {
            listen: DEFAULT_LISTEN_ADDR.to_string(),
            upstream: None,

            upstream_api_key_header: None,
            upstream_api_key_prefix: None,
            fail_mode: "block".to_string(),
            policy_config: Vec::new(),
            agent: None,
            config_name: None,
            max_concurrency: None,
            runtime_registration_id: None,
        }
    }

    #[test]
    fn resolve_policy_config_paths_skips_auto_discovered_defaults_in_connected_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let default_path = dir.path().join("policy-config.yaml");
        std::fs::write(&default_path, "pack:\n  version: 1.0.0\n").expect("write config");

        assert!(resolve_policy_config_paths(&[], true, &default_path).is_empty());
        assert_eq!(
            resolve_policy_config_paths(&[], false, &default_path),
            vec![default_path]
        );
    }

    #[test]
    fn build_runtime_config_with_env_requires_agent_for_policy_config() {
        let mut args = gateway_run_args();
        args.policy_config = vec![PathBuf::from("/tmp/policy-config.yaml")];

        let error = build_runtime_config_with_env(args, None, &GatewayRunEnvironment::default())
            .expect_err("missing agent should fail");

        assert!(error
            .to_string()
            .contains("--policy-config requires --agent"));
    }

    #[test]
    fn build_runtime_config_with_env_uses_connected_mode_defaults_when_unset() {
        let config = build_runtime_config_with_env(
            gateway_run_args(),
            None,
            &GatewayRunEnvironment::default(),
        )
        .expect("runtime config");

        assert_eq!(config.upstream, DYNAMIC_PROVIDER_UPSTREAM_SENTINEL);
        assert_eq!(config.max_concurrency, 16);
        assert!(config.connected_mode);
        assert!(config.upstream_auth.is_none());
        assert!(config.runtime_registration_id.is_none());
    }

    #[test]
    fn build_runtime_config_with_env_uses_hosted_default_upstream_in_disconnected_mode() {
        let config = build_runtime_config_with_env_connected_mode(
            gateway_run_args(),
            None,
            &GatewayRunEnvironment::default(),
            false,
        )
        .expect("runtime config");

        assert_eq!(config.upstream, DEFAULT_HOSTED_UPSTREAM_URL);
        assert!(!config.connected_mode);
    }

    #[test]
    fn build_runtime_config_with_env_prefers_cli_values_and_normalizes_runtime_fields() {
        let mut args = gateway_run_args();
        args.upstream = Some("https://cli-upstream.example.com".to_string());
        args.fail_mode = "allow".to_string();
        args.max_concurrency = Some(0);
        args.runtime_registration_id = Some(" runtime-reg-id ".to_string());

        let env = GatewayRunEnvironment {
            upstream_url: Some("https://env-upstream.example.com".to_string()),
            upstream_api_key: Some("env-secret".to_string()),
            upstream_api_key_header: Some("x-env-key".to_string()),
            upstream_api_key_prefix: Some("Token ".to_string()),
            max_concurrency: Some(42),
            runtime_registration_id: Some("env-reg-id".to_string()),
            ..GatewayRunEnvironment::default()
        };

        let config =
            build_runtime_config_with_env(args, None, &env).expect("runtime config from cli");
        let auth = config.upstream_auth.expect("upstream auth");

        assert_eq!(config.upstream, "https://cli-upstream.example.com");
        assert_eq!(config.fail_mode, crate::gateway::fail_mode::FailMode::Allow);
        assert_eq!(config.max_concurrency, 1);
        assert_eq!(
            config.runtime_registration_id.as_deref(),
            Some("runtime-reg-id")
        );
        assert_eq!(auth.header_name, "x-env-key");
        // The plaintext CLI upstream-api-key flag was removed; the key now comes
        // from the environment, so the CLI-preferred value here is the env secret.
        assert_eq!(auth.header_value, "Token env-secret");
    }

    #[test]
    fn build_runtime_config_with_env_uses_env_values_when_cli_missing() {
        let env = GatewayRunEnvironment {
            upstream_url: Some("https://env-upstream.example.com".to_string()),
            upstream_api_key: Some("env-secret".to_string()),
            upstream_api_key_header: Some("x-env-key".to_string()),
            upstream_api_key_prefix: Some("Token ".to_string()),
            max_concurrency: Some(23),
            runtime_registration_id: Some("   ".to_string()),
            ..GatewayRunEnvironment::default()
        };

        let config = build_runtime_config_with_env(gateway_run_args(), None, &env)
            .expect("runtime config from env");
        let auth = config.upstream_auth.expect("upstream auth");

        assert_eq!(config.upstream, "https://env-upstream.example.com");
        assert_eq!(config.max_concurrency, 23);
        assert_eq!(auth.header_name, "x-env-key");
        assert_eq!(auth.header_value, "Token env-secret");
        assert_eq!(config.runtime_registration_id, None);
    }

    #[test]
    fn build_runtime_config_reads_process_env_and_uses_default_upstream_auth_parts() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();

        crate::test_support::set_var("VERDICTAN_UPSTREAM_URL", "https://env-upstream.example.com");
        crate::test_support::set_var("VERDICTAN_UPSTREAM_API_KEY", "process-secret");
        crate::test_support::set_var("VERDICTAN_GATEWAY_MAX_CONCURRENCY", "7");
        crate::test_support::set_var("VERDICTAN_RUNTIME_REGISTRATION_ID", " process-runtime-id ");

        let config = build_runtime_config(gateway_run_args(), None).expect("runtime config");
        let auth = config.upstream_auth.expect("upstream auth");

        assert_eq!(config.upstream, "https://env-upstream.example.com");
        assert_eq!(config.max_concurrency, 7);
        assert_eq!(
            config.runtime_registration_id.as_deref(),
            Some("process-runtime-id")
        );
        assert_eq!(auth.header_name, "Authorization");
        assert_eq!(auth.header_value, "Bearer process-secret");
    }

    #[test]
    fn build_runtime_config_with_env_sets_source_path_for_single_policy_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("policy-config.yaml");
        std::fs::write(&config_path, "pack:\n  version: 1.2.3\n").expect("write config");

        let mut args = gateway_run_args();
        args.policy_config = vec![config_path.clone()];
        args.agent = Some("agent-1".to_string());

        let config = build_runtime_config_with_env_connected_mode(
            args,
            None,
            &GatewayRunEnvironment::default(),
            false,
        )
        .expect("runtime config");

        assert_eq!(
            config.source_config_path.as_deref(),
            Some(config_path.to_string_lossy().as_ref())
        );
        assert_eq!(config.loaded_config.config_version, "1.2.3");
    }

    #[test]
    fn build_runtime_config_with_env_omits_source_path_for_multiple_policy_configs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base_path = dir.path().join("base.yaml");
        let overlay_path = dir.path().join("overlay.yaml");
        std::fs::write(&base_path, "pack:\n  version: 1.0.0\n").expect("write base");
        std::fs::write(&overlay_path, "pack:\n  version: 2.0.0\n").expect("write overlay");

        let mut args = gateway_run_args();
        args.policy_config = vec![base_path, overlay_path];
        args.agent = Some("agent-1".to_string());

        let config = build_runtime_config_with_env_connected_mode(
            args,
            None,
            &GatewayRunEnvironment::default(),
            false,
        )
        .expect("runtime config");

        assert_eq!(config.source_config_path, None);
        assert_eq!(config.loaded_config.config_version, "2.0.0");
    }

    #[test]
    fn find_agent_id_by_selector_matches_id_or_name() {
        let agents = vec![
            json!({ "id": "agent_1", "name": "Assistant" }),
            json!({ "id": "agent_2", "display_name": "Research agent" }),
            json!({ "agent_id": "agent_3", "resource_name": "Billing helper" }),
        ];

        assert_eq!(
            find_agent_id_by_selector(&agents, "agent_1").expect("id lookup"),
            Some("agent_1".to_string())
        );
        assert_eq!(
            find_agent_id_by_selector(&agents, "Assistant").expect("name lookup"),
            Some("agent_1".to_string())
        );
        assert_eq!(
            find_agent_id_by_selector(&agents, "Research agent").expect("display lookup"),
            Some("agent_2".to_string())
        );
        assert_eq!(
            find_agent_id_by_selector(&agents, "Billing helper").expect("resource lookup"),
            Some("agent_3".to_string())
        );
    }

    #[test]
    fn find_agent_id_by_selector_rejects_ambiguous_names() {
        let agents = vec![
            json!({ "id": "agent_1", "name": "Assistant" }),
            json!({ "id": "agent_2", "name": "Assistant" }),
        ];

        let error = find_agent_id_by_selector(&agents, "Assistant").expect_err("ambiguous name");
        assert!(error.to_string().contains("matched multiple agents"));
    }

    #[test]
    fn find_agent_id_by_selector_prefers_exact_id_match_before_name_matching() {
        let agents = vec![
            json!({ "id": "shared-selector", "name": "Assistant" }),
            json!({ "id": "agent_2", "name": "shared-selector" }),
            json!({ "id": "agent_3", "name": "shared-selector" }),
        ];

        assert_eq!(
            find_agent_id_by_selector(&agents, "shared-selector").expect("selector"),
            Some("shared-selector".to_string())
        );
    }

    #[test]
    fn resolve_event_sink_config_uses_launch_env_token() {
        let args = GatewayRunArgs {
            listen: DEFAULT_LISTEN_ADDR.to_string(),
            upstream: None,

            upstream_api_key_header: None,
            upstream_api_key_prefix: None,
            fail_mode: "block".to_string(),
            policy_config: Vec::new(),
            agent: None,
            config_name: None,
            max_concurrency: None,
            runtime_registration_id: None,
        };
        let env = GatewayRunEnvironment {
            api_token: Some("env-token".to_string()),
            ..GatewayRunEnvironment::default()
        };

        let event_sink =
            resolve_event_sink_config(&args, &env, "https://control-plane.example.com")
                .expect("event sink");

        assert_eq!(event_sink.base_url, "https://control-plane.example.com");
        assert_eq!(event_sink.api_token, "env-token");
        assert_eq!(
            event_sink.gateway_service_token.as_deref(),
            Some("env-token")
        );
    }

    #[test]
    fn resolve_runtime_launch_env_only_seeds_missing_values() {
        let event_sink = crate::gateway::server::EventSinkConfig {
            base_url: "https://control-plane.example.com".to_string(),
            api_token: "runtime-token".to_string(),
            gateway_service_token: None,
        };
        let env = GatewayRunEnvironment {
            api_token: Some("existing-token".to_string()),
            runtime_agent_id: Some("agent-existing".to_string()),
            ..GatewayRunEnvironment::default()
        };

        let launch_env =
            resolve_runtime_launch_env(&env, Some(&event_sink), Some("resolved-agent"));

        assert_eq!(launch_env.api_token, None);
        assert_eq!(launch_env.agent_id, None);
    }

    #[test]
    fn resolve_runtime_launch_env_seeds_from_event_sink_when_env_empty() {
        let event_sink = crate::gateway::server::EventSinkConfig {
            base_url: "https://api.example.com".to_string(),
            api_token: "sink-token".to_string(),
            gateway_service_token: None,
        };
        let env = GatewayRunEnvironment::default();

        let launch_env =
            resolve_runtime_launch_env(&env, Some(&event_sink), Some("resolved-agent-id"));

        assert_eq!(launch_env.api_token, Some("sink-token".to_string()));
        assert_eq!(launch_env.agent_id, Some("resolved-agent-id".to_string()));
    }

    #[test]
    fn resolve_runtime_launch_env_skips_whitespace_only_resolved_agent() {
        let event_sink = crate::gateway::server::EventSinkConfig {
            base_url: "https://api.example.com".to_string(),
            api_token: "tok".to_string(),
            gateway_service_token: None,
        };
        let env = GatewayRunEnvironment::default();

        let launch_env = resolve_runtime_launch_env(&env, Some(&event_sink), Some("   "));
        assert_eq!(launch_env.agent_id, None);
    }

    #[test]
    fn resolve_runtime_launch_env_trims_seeded_values_when_existing_env_is_blank() {
        let event_sink = crate::gateway::server::EventSinkConfig {
            base_url: "https://api.example.com".to_string(),
            api_token: "  sink-token  ".to_string(),
            gateway_service_token: None,
        };
        let env = GatewayRunEnvironment {
            api_token: Some("   ".to_string()),
            runtime_agent_id: Some("  ".to_string()),
            ..GatewayRunEnvironment::default()
        };

        let launch_env =
            resolve_runtime_launch_env(&env, Some(&event_sink), Some(" resolved-agent "));

        assert_eq!(launch_env.api_token.as_deref(), Some("sink-token"));
        assert_eq!(launch_env.agent_id.as_deref(), Some("resolved-agent"));
    }

    #[test]
    fn trimmed_non_empty_handles_edge_cases() {
        use super::trimmed_non_empty;
        assert_eq!(trimmed_non_empty(""), None);
        assert_eq!(trimmed_non_empty("   "), None);
        assert_eq!(trimmed_non_empty("hello"), Some("hello".to_string()));
        assert_eq!(trimmed_non_empty("  hello  "), Some("hello".to_string()));
    }

    #[test]
    fn find_agent_id_by_selector_returns_none_for_missing() {
        let agents = vec![json!({ "id": "agent_1", "name": "A" })];
        assert_eq!(
            find_agent_id_by_selector(&agents, "nonexistent").unwrap(),
            None
        );
    }

    #[test]
    fn find_agent_id_by_selector_skips_empty_and_whitespace() {
        let agents = vec![json!({ "id": "agent_1", "name": "A" })];
        assert_eq!(find_agent_id_by_selector(&agents, "").unwrap(), None);
        assert_eq!(find_agent_id_by_selector(&agents, "   ").unwrap(), None);
    }

    #[test]
    fn resolve_event_sink_config_returns_none_without_tokens() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();
        let args = GatewayRunArgs {
            listen: DEFAULT_LISTEN_ADDR.to_string(),
            upstream: None,

            upstream_api_key_header: None,
            upstream_api_key_prefix: None,
            fail_mode: "block".to_string(),
            policy_config: Vec::new(),
            agent: None,
            config_name: None,
            max_concurrency: None,
            runtime_registration_id: None,
        };
        let env = GatewayRunEnvironment::default();
        let result = resolve_event_sink_config(&args, &env, "https://api.example.com");
        assert!(result.is_none());
    }

    #[test]
    fn resolve_event_sink_config_uses_trimmed_launch_env_token() {
        let args = GatewayRunArgs {
            listen: DEFAULT_LISTEN_ADDR.to_string(),
            upstream: None,

            upstream_api_key_header: None,
            upstream_api_key_prefix: None,
            fail_mode: "block".to_string(),
            policy_config: Vec::new(),
            agent: None,
            config_name: None,
            max_concurrency: None,
            runtime_registration_id: None,
        };
        let env = GatewayRunEnvironment {
            api_token: Some("  env-tok  ".to_string()),
            ..GatewayRunEnvironment::default()
        };
        let sink = resolve_event_sink_config(&args, &env, "https://api.x.com").unwrap();
        assert_eq!(sink.api_token, "env-tok");
    }

    #[test]
    fn run_returns_invalid_fail_mode_error_before_runtime_start() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();

        let mut args = gateway_run_args();
        args.fail_mode = "invalid".to_string();

        let error = run(args).expect_err("invalid fail mode should fail");
        assert!(error
            .to_string()
            .contains("invalid --fail-mode (expected allow|block)"));
    }

    #[tokio::test]
    async fn ensure_agent_config_creates_resources_and_posts_merged_yaml() {
        let state = MockControlPlaneState::default();
        let server = spawn_mock_control_plane(state.clone()).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let base_path = dir.path().join("base-policy.yaml");
        let overlay_path = dir.path().join("overlay-policy.yaml");
        std::fs::write(&base_path, "pack:\n  name: base\n").expect("write base policy");
        std::fs::write(&overlay_path, "targets:\n  - demo\n").expect("write overlay policy");

        let agent_id = ensure_agent_config(
            server.url(),
            "test-token",
            "Assistant",
            "baseline",
            &[base_path.clone(), overlay_path.clone()],
        )
        .await
        .expect("ensure agent config");

        assert_eq!(agent_id, "agent-created");

        let requests = state.requests();
        assert_eq!(requests.len(), 5);
        assert_eq!(
            requests
                .iter()
                .map(|request| (request.method, request.path.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("GET", "/v1/agents"),
                ("POST", "/v1/agents"),
                ("GET", "/v1/configurations"),
                ("POST", "/v1/configurations"),
                ("POST", "/v1/configurations/config-created/versions"),
            ]
        );
        assert!(requests
            .iter()
            .all(|request| request.authorization.as_deref() == Some("Bearer test-token")));
        assert_eq!(
            requests[1].body.as_ref().expect("create agent body"),
            &json!({ "name": "Assistant" })
        );
        assert_eq!(
            requests[3]
                .body
                .as_ref()
                .expect("create configuration body"),
            &json!({
                "name": "baseline",
                "agent_id": "agent-created",
            })
        );
        assert_eq!(
            requests[4].body.as_ref().expect("save version body"),
            &json!({
                "yaml": "pack:\n  name: base\n\n---\ntargets:\n  - demo\n",
                "deploy": true,
            })
        );
    }

    #[tokio::test]
    async fn ensure_agent_config_reuses_existing_resources_when_names_match() {
        let state = MockControlPlaneState::default();
        *state.agents_response.lock().expect("agents response lock") = json!({
            "agents": [{ "id": "agent-existing", "name": "Assistant" }]
        });
        *state
            .configurations_response
            .lock()
            .expect("configurations response lock") = json!({
            "configurations": [{ "id": "config-existing", "name": "baseline" }]
        });
        let server = spawn_mock_control_plane(state.clone()).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_path = dir.path().join("baseline.yaml");
        std::fs::write(&policy_path, "pack:\n  version: 1.0.0\n").expect("write policy");

        let agent_id = ensure_agent_config(
            server.url(),
            "test-token",
            "Assistant",
            "baseline",
            &[policy_path],
        )
        .await
        .expect("ensure agent config");

        assert_eq!(agent_id, "agent-existing");
        assert_eq!(
            state
                .requests()
                .iter()
                .map(|request| (request.method, request.path.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("GET", "/v1/agents"),
                ("GET", "/v1/configurations"),
                ("POST", "/v1/configurations/config-existing/versions"),
            ]
        );
    }

    #[tokio::test]
    async fn ensure_agent_config_returns_user_error_for_missing_policy_file() {
        let state = MockControlPlaneState::default();
        *state.agents_response.lock().expect("agents response lock") = json!({
            "agents": [{ "id": "agent-existing", "name": "Assistant" }]
        });
        let server = spawn_mock_control_plane(state.clone()).await;
        let missing_path = PathBuf::from("/definitely/missing/policy-config.yaml");

        let error = ensure_agent_config(
            server.url(),
            "test-token",
            "Assistant",
            "baseline",
            &[missing_path.clone()],
        )
        .await
        .expect_err("missing policy file should fail");

        assert!(error
            .to_string()
            .contains("failed to read policy config /definitely/missing/policy-config.yaml"));
        assert_eq!(
            state
                .requests()
                .iter()
                .map(|request| (request.method, request.path.as_str()))
                .collect::<Vec<_>>(),
            vec![("GET", "/v1/agents")]
        );
    }

    #[tokio::test]
    async fn run_async_requires_api_token_to_sync_policy_config() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();

        let mut args = gateway_run_args();
        args.agent = Some("Assistant".to_string());
        args.policy_config = vec![PathBuf::from("/tmp/policy-config.yaml")];

        let error = run_async(args)
            .await
            .expect_err("missing token should fail before runtime start");

        assert!(error
            .to_string()
            .contains("--agent requires an API token to sync with the control plane"));
    }

    #[tokio::test]
    async fn run_async_syncs_policy_config_before_runtime_build() {
        let state = MockControlPlaneState::default();
        let server = spawn_mock_control_plane(state.clone()).await;
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();
        crate::test_support::set_var("VERDICTAN_API_URL", server.url());

        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("baseline-policy.yaml");
        std::fs::write(&config_path, "pack:\n  name: sync\n").expect("write policy");

        let mut args = gateway_run_args();
        args.agent = Some("Assistant".to_string());
        args.policy_config = vec![config_path];
        crate::test_support::set_var("VERDICTAN_API_TOKEN", "admin-token");
        args.fail_mode = "invalid".to_string();

        let error = run_async(args)
            .await
            .expect_err("invalid fail mode should stop before runtime start");

        assert!(error
            .to_string()
            .contains("invalid --fail-mode (expected allow|block)"));
        assert_eq!(
            state
                .requests()
                .iter()
                .map(|request| (request.method, request.path.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("GET", "/v1/agents"),
                ("POST", "/v1/agents"),
                ("GET", "/v1/configurations"),
                ("POST", "/v1/configurations"),
                ("POST", "/v1/configurations/config-created/versions"),
            ]
        );
        assert_eq!(
            state.requests()[3]
                .body
                .as_ref()
                .expect("create configuration body"),
            &json!({
                "name": "baseline-policy",
                "agent_id": "agent-created",
            })
        );
    }

    #[tokio::test]
    async fn run_async_requires_api_token_to_resolve_agent_selector() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();

        let mut args = gateway_run_args();
        args.agent = Some("Assistant".to_string());

        let error = run_async(args)
            .await
            .expect_err("missing token should fail before runtime start");

        assert!(error.to_string().contains(
            "--agent or VERDICTAN_AGENT_NAME requires an API token to resolve the agent"
        ));
    }

    #[tokio::test]
    async fn run_async_resolves_agent_selector_before_runtime_build() {
        let state = MockControlPlaneState::default();
        *state.agents_response.lock().expect("agents response lock") = json!({
            "agents": [{ "agent_id": "agent-resolved", "display_name": "Assistant" }]
        });
        let server = spawn_mock_control_plane(state.clone()).await;
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();
        crate::test_support::set_var("VERDICTAN_API_URL", server.url());

        let mut args = gateway_run_args();
        args.agent = Some("Assistant".to_string());
        crate::test_support::set_var("VERDICTAN_API_TOKEN", "admin-token");
        args.fail_mode = "invalid".to_string();

        let error = run_async(args)
            .await
            .expect_err("invalid fail mode should stop before runtime start");

        assert!(error
            .to_string()
            .contains("invalid --fail-mode (expected allow|block)"));
        assert_eq!(
            state
                .requests()
                .iter()
                .map(|request| (request.method, request.path.as_str()))
                .collect::<Vec<_>>(),
            vec![("GET", "/v1/agents")]
        );
    }

    #[tokio::test]
    async fn run_async_returns_not_found_when_agent_selector_is_missing() {
        let state = MockControlPlaneState::default();
        *state.agents_response.lock().expect("agents response lock") = json!({
            "agents": [{ "id": "agent-1", "name": "Different agent" }]
        });
        let server = spawn_mock_control_plane(state.clone()).await;
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();
        crate::test_support::set_var("VERDICTAN_API_URL", server.url());

        let mut args = gateway_run_args();
        args.agent = Some("Missing agent".to_string());
        crate::test_support::set_var("VERDICTAN_API_TOKEN", "admin-token");

        let error = run_async(args)
            .await
            .expect_err("missing agent should fail");

        assert!(error
            .to_string()
            .contains("agent 'Missing agent' was not found on the control plane"));
        assert_eq!(
            state
                .requests()
                .iter()
                .map(|request| (request.method, request.path.as_str()))
                .collect::<Vec<_>>(),
            vec![("GET", "/v1/agents")]
        );
    }

    #[test]
    fn resolve_policy_config_paths_returns_explicit_paths_regardless_of_connected_mode() {
        let paths = vec![std::path::PathBuf::from("/a.yaml")];
        let result = resolve_policy_config_paths(&paths, true, Path::new("/nonexistent"));
        assert_eq!(result, paths);
    }

    #[test]
    fn resolve_policy_config_paths_returns_empty_when_default_missing() {
        let result = resolve_policy_config_paths(&[], false, Path::new("/does/not/exist.yaml"));
        assert!(result.is_empty());
    }

    #[test]
    fn gateway_run_environment_from_process_reads_trimmed_values() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();

        crate::test_support::set_var("VERDICTAN_API_URL", " https://cp.example.com ");
        crate::test_support::set_var("VERDICTAN_API_TOKEN", "token-value");
        crate::test_support::set_var("VERDICTAN_UPSTREAM_URL", "https://upstream.example.com");
        crate::test_support::set_var("VERDICTAN_UPSTREAM_API_KEY", "upstream-key");
        crate::test_support::set_var("VERDICTAN_UPSTREAM_API_KEY_HEADER", "x-api-key");
        crate::test_support::set_var("VERDICTAN_UPSTREAM_API_KEY_PREFIX", "Token ");
        crate::test_support::set_var("VERDICTAN_GATEWAY_MAX_CONCURRENCY", "  not-a-number ");
        crate::test_support::set_var(
            "VERDICTAN_RUNTIME_REGISTRATION_ID",
            " 11111111-1111-1111-1111-111111111111 ",
        );
        crate::test_support::set_var("VERDICTAN_AGENT_ID", " agent-123 ");
        crate::test_support::set_var("VERDICTAN_AGENT_NAME", " assistant-selector ");

        let env = GatewayRunEnvironment::from_process();

        assert_eq!(env.api_base_url.as_deref(), Some("https://cp.example.com"));
        assert_eq!(env.api_token.as_deref(), Some("token-value"));
        assert_eq!(
            env.upstream_url.as_deref(),
            Some("https://upstream.example.com")
        );
        assert_eq!(env.upstream_api_key.as_deref(), Some("upstream-key"));
        assert_eq!(env.upstream_api_key_header.as_deref(), Some("x-api-key"));
        assert_eq!(env.upstream_api_key_prefix.as_deref(), Some("Token "));
        assert_eq!(env.max_concurrency, None);
        assert_eq!(
            env.runtime_registration_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(env.runtime_agent_id.as_deref(), Some("agent-123"));
        assert_eq!(
            env.runtime_agent_selector.as_deref(),
            Some("assistant-selector")
        );
    }

    #[test]
    fn gateway_run_environment_reads_trimmed_agent_name_env() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();

        crate::test_support::set_var("VERDICTAN_AGENT_NAME", " primary-agent ");

        let env = GatewayRunEnvironment::from_process();

        assert_eq!(env.runtime_agent_selector.as_deref(), Some("primary-agent"));
    }

    #[test]
    fn gateway_runtime_launch_env_applies_only_present_values() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();

        GatewayRuntimeLaunchEnv {
            api_token: Some("runtime-token".to_string()),
            agent_id: Some("agent-live".to_string()),
        }
        .apply_to_process_env();

        assert_eq!(
            std::env::var("VERDICTAN_API_TOKEN").ok().as_deref(),
            Some("runtime-token")
        );
        assert_eq!(
            std::env::var("VERDICTAN_AGENT_ID").ok().as_deref(),
            Some("agent-live")
        );
    }

    #[test]
    fn resolve_api_base_url_defaults_to_hosted_control_plane() {
        assert_eq!(
            resolve_api_base_url(&GatewayRunEnvironment::default()),
            "https://api.verdictan.com"
        );
        assert_eq!(
            resolve_api_base_url(&GatewayRunEnvironment {
                api_base_url: Some("https://override.example.com".to_string()),
                ..GatewayRunEnvironment::default()
            }),
            "https://override.example.com"
        );
    }

    #[test]
    fn configured_runtime_agent_selector_prefers_cli_agent_then_env_selector() {
        let args = GatewayRunArgs {
            listen: DEFAULT_LISTEN_ADDR.to_string(),
            upstream: None,

            upstream_api_key_header: None,
            upstream_api_key_prefix: None,
            fail_mode: "block".to_string(),
            policy_config: Vec::new(),
            agent: Some(" cli-agent ".to_string()),
            config_name: None,
            max_concurrency: None,
            runtime_registration_id: None,
        };

        let env = GatewayRunEnvironment {
            runtime_agent_selector: Some("env-agent".to_string()),
            ..GatewayRunEnvironment::default()
        };

        assert_eq!(
            configured_runtime_agent_selector(&args, &env).as_deref(),
            Some("cli-agent")
        );
        assert_eq!(
            configured_runtime_agent_selector(
                &GatewayRunArgs {
                    agent: None,
                    ..args
                },
                &env
            )
            .as_deref(),
            Some("env-agent")
        );
    }

    #[test]
    fn configured_runtime_agent_selector_ignores_whitespace_cli_agent() {
        let mut args = gateway_run_args();
        args.agent = Some("   ".to_string());

        let env = GatewayRunEnvironment {
            runtime_agent_selector: Some("env-agent".to_string()),
            ..GatewayRunEnvironment::default()
        };

        assert_eq!(
            configured_runtime_agent_selector(&args, &env).as_deref(),
            Some("env-agent")
        );
    }

    #[test]
    fn configured_runtime_agent_selector_returns_none_when_both_empty() {
        let mut args = gateway_run_args();
        args.agent = None;

        let env = GatewayRunEnvironment::default();

        assert_eq!(configured_runtime_agent_selector(&args, &env), None);
    }

    #[test]
    fn resolve_policy_config_paths_uses_default_when_file_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let default_path = dir.path().join("policy-config.yaml");
        std::fs::write(&default_path, "pack: {}").expect("write");
        let result = resolve_policy_config_paths(&[], false, &default_path);
        assert_eq!(result, vec![default_path]);
    }

    #[test]
    fn resolve_policy_config_paths_connected_mode_ignores_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let default_path = dir.path().join("policy-config.yaml");
        std::fs::write(&default_path, "pack: {}").expect("write");
        let result = resolve_policy_config_paths(&[], true, &default_path);
        assert!(result.is_empty());
    }

    #[test]
    fn trimmed_non_empty_returns_none_for_empty() {
        assert_eq!(trimmed_non_empty(""), None);
        assert_eq!(trimmed_non_empty("   "), None);
    }

    #[test]
    fn trimmed_non_empty_trims_value() {
        assert_eq!(trimmed_non_empty(" hello "), Some("hello".to_string()));
    }

    #[test]
    fn trimmed_non_empty_preserves_untrimmed_value() {
        assert_eq!(trimmed_non_empty("hello"), Some("hello".to_string()));
    }

    #[test]
    fn gateway_runtime_launch_env_skips_none_values() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");
        let _env = reset_gateway_run_env();
        crate::test_support::unset_var("VERDICTAN_API_TOKEN");
        crate::test_support::unset_var("VERDICTAN_AGENT_ID");

        GatewayRuntimeLaunchEnv {
            api_token: None,
            agent_id: None,
        }
        .apply_to_process_env();

        assert!(std::env::var("VERDICTAN_API_TOKEN").is_err());
        assert!(std::env::var("VERDICTAN_AGENT_ID").is_err());
    }

    #[test]
    fn resolve_runtime_launch_env_skips_when_process_env_already_set() {
        let env = GatewayRunEnvironment {
            api_token: Some("existing-token".to_string()),
            runtime_agent_id: Some("existing-agent".to_string()),
            ..GatewayRunEnvironment::default()
        };
        let sink = crate::gateway::server::EventSinkConfig {
            base_url: "http://api.test".to_string(),
            api_token: "sink-token".to_string(),
            gateway_service_token: None,
        };
        let launch_env = resolve_runtime_launch_env(&env, Some(&sink), Some("resolved-agent"));
        assert_eq!(launch_env.api_token, None);
        assert_eq!(launch_env.agent_id, None);
    }

    #[test]
    fn resolve_runtime_launch_env_uses_sink_when_env_empty() {
        let env = GatewayRunEnvironment::default();
        let sink = crate::gateway::server::EventSinkConfig {
            base_url: "http://api.test".to_string(),
            api_token: "sink-token".to_string(),
            gateway_service_token: None,
        };
        let launch_env = resolve_runtime_launch_env(&env, Some(&sink), Some("resolved-agent"));
        assert_eq!(launch_env.api_token.as_deref(), Some("sink-token"));
        assert_eq!(launch_env.agent_id.as_deref(), Some("resolved-agent"));
    }
}

#[cfg(test)]
mod coverage_expansion_gateway_run_tests {
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

    // ── Constants ───────────────────────────────────────────────────────

    #[test]
    fn dynamic_provider_upstream_sentinel() {
        assert_eq!(
            DYNAMIC_PROVIDER_UPSTREAM_SENTINEL,
            "http://verdictan-dynamic-provider.invalid"
        );
    }

    #[test]
    fn default_hosted_upstream_url() {
        assert_eq!(DEFAULT_HOSTED_UPSTREAM_URL, "https://api.verdictan.com");
    }

    #[test]
    fn default_listen_addr() {
        assert_eq!(DEFAULT_LISTEN_ADDR, "0.0.0.0:41002");
    }

    // ── GatewayRunEnvironment ───────────────────────────────────────────

    #[test]
    fn gateway_run_environment_default() {
        let env = GatewayRunEnvironment::default();
        assert!(env.api_base_url.is_none());
        assert!(env.api_token.is_none());
        assert!(env.upstream_url.is_none());
        assert!(env.upstream_api_key.is_none());
        assert!(env.upstream_api_key_header.is_none());
        assert!(env.upstream_api_key_prefix.is_none());
        assert!(env.max_concurrency.is_none());
        assert!(env.runtime_registration_id.is_none());
        assert!(env.runtime_agent_id.is_none());
        assert!(env.runtime_agent_selector.is_none());
    }

    #[test]
    fn gateway_run_environment_eq() {
        let env1 = GatewayRunEnvironment::default();
        let env2 = GatewayRunEnvironment::default();
        assert_eq!(env1, env2);
    }

    // ── GatewayRuntimeLaunchEnv ─────────────────────────────────────────

    #[test]
    fn gateway_runtime_launch_env_default() {
        let env = GatewayRuntimeLaunchEnv::default();
        assert!(env.api_token.is_none());
        assert!(env.agent_id.is_none());
    }
}
