// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Server section module.
//! Child of `gateway::server`; parent private items remain visible via `use crate::gateway::*`.
use super::*;

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ReloadGatewayConfigRequest {
    pub(crate) config_yaml: Option<String>,
    pub(crate) config_path: Option<String>,
    pub(crate) clear_active: Option<bool>,
}

pub(crate) fn active_gateway_config(config: &LoadedDeclarativeConfig) -> ActiveGatewayConfig {
    let targeting: Vec<serde_json::Value> = config
        .chain_entries
        .iter()
        .filter_map(|entry| {
            let t = entry.targeting()?;
            Some(serde_json::json!({
                "policy": entry.kind(),
                "scope": match t.scope {
                    enforcement::TargetingScope::Organization => "organization",
                    enforcement::TargetingScope::Team => "team",
                },
                "teams": t.teams,
                "gateways": serde_json::to_value(&t.gateways).unwrap_or(serde_json::Value::Null),
            }))
        })
        .collect();

    ActiveGatewayConfig {
        mode: "declarative",
        config_version: config.config_version.clone(),
        config_sha256: config.config_sha256.clone(),
        config_content: config.raw_yaml.clone(),
        policy_count: config.chain_entries.len(),
        policy_chain: config
            .chain_entries
            .iter()
            .map(|e| e.kind().to_string())
            .collect(),
        targeting,
    }
}

pub(crate) fn extract_config_version(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("version:") {
            let value = rest.trim().trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}

pub(crate) async fn read_source_gateway_config(source_path: Option<&str>) -> SourceGatewayConfig {
    let Some(path) = source_path.map(str::trim).filter(|value| !value.is_empty()) else {
        return SourceGatewayConfig {
            path: None,
            exists: false,
            config_version: None,
            config_sha256: None,
            bytes: None,
            updated_at: None,
            content: None,
            read_error: None,
        };
    };

    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let text = match String::from_utf8(bytes.clone()) {
                Ok(text) => text,
                Err(error) => {
                    return SourceGatewayConfig {
                        path: Some(path.to_string()),
                        exists: false,
                        config_version: None,
                        config_sha256: None,
                        bytes: None,
                        updated_at: None,
                        content: None,
                        read_error: Some(format!("config is not valid UTF-8: {error}")),
                    };
                }
            };

            let updated_at = tokio::fs::metadata(path)
                .await
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .map(|modified| DateTime::<Utc>::from(modified).to_rfc3339());

            SourceGatewayConfig {
                path: Some(path.to_string()),
                exists: true,
                config_version: extract_config_version(&text),
                config_sha256: Some(crate::gateway::declarative_config::sha256_prefixed(&bytes)),
                bytes: Some(bytes.len() as u64),
                updated_at,
                content: Some(text),
                read_error: None,
            }
        }
        Err(error) => SourceGatewayConfig {
            path: Some(path.to_string()),
            exists: false,
            config_version: None,
            config_sha256: None,
            bytes: None,
            updated_at: None,
            content: None,
            read_error: Some(error.to_string()),
        },
    }
}

pub async fn spawn_with_policy(
    listen: std::net::SocketAddr,
    upstream_base: String,
    upstream_auth: Option<UpstreamAuthConfig>,
    fail_mode: FailMode,
    event_sink: Option<EventSinkConfig>,
    loaded_config: LoadedDeclarativeConfig,
    max_concurrency: usize,
) -> Result<GatewayHandle, CliError> {
    let mut config = crate::runtime::RuntimeInstanceConfig::new(
        None,
        listen,
        upstream_base,
        upstream_auth,
        fail_mode,
        loaded_config,
        max_concurrency,
        true,
        event_sink,
    );
    config.connected_mode = crate::gateway::gateway_env::gateway_control_plane_connected();
    spawn_instance(config).await
}

pub(crate) fn env_flag_enabled(name: &str) -> bool {
    optional_env(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub fn resolve_admin_bearer_token(
    admin_local_only: bool,
    control_plane_available: bool,
) -> Option<String> {
    if let Some(token) = optional_env("VERDICTAN_API_TOKEN") {
        return Some(token);
    }

    if admin_local_only && !control_plane_available {
        return None;
    }

    let secret = generate_random_admin_secret();
    if let Some(path) = write_admin_secret_file(&secret) {
        tracing::info!(
            path = %path.display(),
            "generated admin secret (no VERDICTAN_API_TOKEN configured)"
        );
    } else {
        tracing::info!(
            "generated admin secret (no VERDICTAN_API_TOKEN configured; file write skipped)"
        );
    }
    Some(secret)
}

pub(crate) fn generate_random_admin_secret() -> String {
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    format!("{}{}", a.as_simple(), b.as_simple())
}

pub(crate) fn write_admin_secret_file(secret: &str) -> Option<std::path::PathBuf> {
    let dir = if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        std::path::PathBuf::from(runtime_dir).join("verdictan")
    } else if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home).join(".verdictan")
    } else {
        std::env::temp_dir().join("verdictan")
    };

    if std::fs::create_dir_all(&dir).is_err() {
        tracing::debug!(path = %dir.display(), "could not create admin secret directory");
        return None;
    }

    #[cfg(windows)]
    {
        let _ = crate::windows_private_acl::restrict_path_to_owner(&dir);
    }

    let path = dir.join("admin.secret");
    match crate::persistence::atomic_write_private(&path, secret.as_bytes()) {
        Ok(protection) => {
            if protection == crate::persistence::PrivateFileMode::Unsupported {
                report_unrestricted_admin_secret_file(&path);
            }
            Some(path)
        }
        Err(error) => {
            tracing::debug!(
                path = %path.display(),
                error = %error,
                "could not write admin secret file"
            );
            None
        }
    }
}

fn report_unrestricted_admin_secret_file(path: &std::path::Path) {
    let target = std::env::consts::OS;
    tracing::warn!(
        path = %path.display(),
        target_os = target,
        "wrote an admin secret file without an owner-only file mode"
    );
    eprintln!(
        "warning: {} holds an admin secret and could not receive an owner-only \
         file mode on {target}. Restrict access to this file before you leave the host.",
        path.display()
    );
}

/// Pull the gateway's assigned configuration YAML from the control-plane API.
/// Returns gateway identity metadata even when no configuration YAML is assigned.
pub(crate) fn gateway_config_pull_url(
    base_url: &str,
    runtime_registration_id: Option<&str>,
    region: Option<&str>,
) -> String {
    let base_url = format!("{}/v1/gateway/config/pull", base_url.trim_end_matches('/'));
    let mut params = Vec::new();
    if let Some(rid) = runtime_registration_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        params.push(format!(
            "runtime_registration_id={}",
            urlencoding::encode(rid)
        ));
    }
    if let Some(r) = region.map(str::trim).filter(|v| !v.is_empty()) {
        params.push(format!("region={}", urlencoding::encode(r)));
    }
    if params.is_empty() {
        base_url
    } else {
        format!("{base_url}?{}", params.join("&"))
    }
}

pub(crate) fn validate_pulled_catalog_price(
    value: Option<String>,
    provider_id: &str,
    model_id: &str,
    field: &str,
) -> anyhow::Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    crate::gateway::provider_catalog::parse_exact_catalog_price(&value).map_err(|reason| {
        anyhow::anyhow!(
            "config pull returned invalid catalog price for provider '{provider_id}', model '{model_id}', field '{field}': {reason}"
        )
    })?;
    Ok(Some(value))
}

pub(crate) async fn pull_config_from_api(
    sink: &EventSink,
    runtime_registration_id: Option<&str>,
) -> anyhow::Result<PulledGatewayConfig> {
    let client = sink.machine_client()?;
    let effective_region = std::env::var("VERDICTAN_REGION").ok();
    let url = gateway_config_pull_url(
        &sink.base_url,
        runtime_registration_id,
        effective_region.as_deref(),
    );

    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("config pull failed: status={status} body={body}");
    }

    #[derive(serde::Deserialize)]
    struct PullPublicationCatalogEntry {
        pub(crate) family_key: Option<String>,
        pub(crate) publication_key: Option<String>,
        pub(crate) published_hostname: Option<String>,
        pub(crate) publication_state: Option<String>,
        pub(crate) locality_mode: Option<String>,
        pub(crate) serving_fleet_class: Option<String>,
        pub(crate) active_revision_id: Option<String>,
        pub(crate) agent_id: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct PullPublicationCatalogFeed {
        pub(crate) publications: Option<Vec<PullPublicationCatalogEntry>>,
    }

    #[derive(serde::Deserialize)]
    struct PullRoutingCompatibilityEntry {
        pub(crate) publication_key: Option<String>,
        pub(crate) active_revision_id: Option<String>,
        pub(crate) primary_region_group_key: Option<String>,
        pub(crate) compatibility_digest: Option<String>,
        pub(crate) auth_digest: Option<String>,
        pub(crate) policy_digest: Option<String>,
        pub(crate) runtime_manifest_digest: Option<String>,
        pub(crate) readiness_state: Option<String>,
        pub(crate) admitted_members: Option<serde_json::Value>,
    }

    #[derive(serde::Deserialize)]
    struct PullRoutingCompatibilityFeed {
        pub(crate) region_key: Option<String>,
        pub(crate) publications: Option<Vec<PullRoutingCompatibilityEntry>>,
    }

    #[derive(serde::Deserialize)]
    struct PullPeerGatewayEntry {
        pub(crate) agent_id: Option<String>,
        pub(crate) gateway_id: Option<String>,
        pub(crate) relay_endpoint: Option<String>,
        pub(crate) readiness: Option<String>,
        pub(crate) region: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct PullCatalogModelEntry {
        pub(crate) id: String,
        pub(crate) provider_id: String,
        #[serde(default)]
        pub(crate) model_type: String,
        pub(crate) context_window: Option<i32>,
        pub(crate) max_output_tokens: Option<i32>,
        #[serde(default)]
        pub(crate) supported_features: Vec<String>,
        #[serde(default)]
        pub(crate) parameter_overrides: serde_json::Map<String, serde_json::Value>,
        #[serde(default)]
        pub(crate) removed_params: Vec<String>,
        pub(crate) input_token_price: Option<String>,
        pub(crate) output_token_price: Option<String>,
        pub(crate) cached_input_read_price: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct PullResponse {
        #[serde(default)]
        pub(crate) catalog_version: i64,
        pub(crate) gateway_id: Option<String>,
        pub(crate) runtime_registration_id: Option<String>,
        pub(crate) publication_catalog: Option<PullPublicationCatalogFeed>,
        pub(crate) routing_compatibility: Option<PullRoutingCompatibilityFeed>,
        #[serde(default)]
        pub(crate) peer_gateways: Option<Vec<PullPeerGatewayEntry>>,
        pub(crate) relay_hmac_secret: Option<String>,
        pub(crate) model_catalog: Option<Vec<PullCatalogModelEntry>>,
        pub(crate) yaml: Option<String>,
    }

    let requested_runtime_registration_id = runtime_registration_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let PullResponse {
        catalog_version,
        gateway_id,
        runtime_registration_id,
        publication_catalog: publication_catalog_feed,
        routing_compatibility: routing_compatibility_feed,
        peer_gateways: pulled_peer_gateways,
        relay_hmac_secret,
        model_catalog,
        yaml,
    } = response.json().await?;
    let gateway_id = normalize_optional_owned(gateway_id);
    let runtime_registration_id =
        normalize_optional_owned(runtime_registration_id).or(requested_runtime_registration_id);
    let region_key = routing_compatibility_feed
        .as_ref()
        .and_then(|value| normalize_optional_owned(value.region_key.clone()))
        .filter(|value| !value.is_empty());
    let mut publication_catalog = Vec::new();
    let mut routing_compatibility = Vec::new();
    let catalog_entries = publication_catalog_feed
        .and_then(|value| value.publications)
        .unwrap_or_default();
    let routing_entries = routing_compatibility_feed
        .and_then(|value| value.publications)
        .unwrap_or_default();

    for entry in catalog_entries {
        let Some(family_key) = normalize_optional_owned(entry.family_key) else {
            continue;
        };
        let Some(publication_key) = normalize_optional_owned(entry.publication_key) else {
            continue;
        };
        publication_catalog.push(
            crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
                family_key,
                publication_key,
                published_hostname: normalize_optional_owned(entry.published_hostname),
                publication_state: normalize_optional_owned(entry.publication_state)
                    .unwrap_or_else(|| "draft".to_string()),
                active_revision_id: normalize_optional_owned(entry.active_revision_id),
                locality_mode: normalize_optional_owned(entry.locality_mode)
                    .unwrap_or_else(|| "region_pinned".to_string()),
                serving_fleet_class: normalize_optional_owned(entry.serving_fleet_class)
                    .unwrap_or_else(|| "connected_cell_pool".to_string()),
                agent_id: normalize_optional_owned(entry.agent_id),
            },
        );
    }

    for entry in routing_entries {
        let Some(publication_key) = normalize_optional_owned(entry.publication_key) else {
            continue;
        };
        let active_revision_id = normalize_optional_owned(entry.active_revision_id);
        let serving_fleet_class = publication_catalog
            .iter()
            .find(|publication| {
                publication.publication_key == publication_key
                    && publication.active_revision_id == active_revision_id
            })
            .map(|publication| publication.serving_fleet_class.as_str())
            .unwrap_or("connected_cell_pool");
        let active_revision_pool_membership_issue =
            active_revision_pool_membership_issue_for_gateway(
                serving_fleet_class,
                runtime_registration_id.as_deref(),
                gateway_id.as_deref(),
                entry.admitted_members.as_ref(),
            )
            .map(str::to_string);
        routing_compatibility.push(
            crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor {
                publication_key,
                active_revision_id,
                primary_region_group_key: normalize_optional_owned(entry.primary_region_group_key),
                readiness_state: normalize_optional_owned(entry.readiness_state),
                compatibility_digest: normalize_optional_owned(entry.compatibility_digest),
                auth_digest: normalize_optional_owned(entry.auth_digest),
                policy_digest: normalize_optional_owned(entry.policy_digest),
                runtime_manifest_digest: normalize_optional_owned(entry.runtime_manifest_digest),
                active_revision_pool_membership_issue,
            },
        );
    }
    let peer_gateways: Vec<crate::runtime::PeerGatewayDescriptor> = pulled_peer_gateways
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| {
            Some(crate::runtime::PeerGatewayDescriptor {
                agent_id: entry.agent_id?,
                gateway_id: entry.gateway_id?,
                relay_endpoint: entry.relay_endpoint,
                readiness: entry.readiness.unwrap_or_else(|| "unknown".to_string()),
                region: entry.region,
            })
        })
        .collect();

    let catalog_snapshot = if let Some(model_catalog) = model_catalog {
        let models = model_catalog
            .into_iter()
            .map(|entry| {
                let input_token_price = validate_pulled_catalog_price(
                    entry.input_token_price,
                    &entry.provider_id,
                    &entry.id,
                    "input_token_price",
                )?;
                let output_token_price = validate_pulled_catalog_price(
                    entry.output_token_price,
                    &entry.provider_id,
                    &entry.id,
                    "output_token_price",
                )?;
                let cached_input_read_price = validate_pulled_catalog_price(
                    entry.cached_input_read_price,
                    &entry.provider_id,
                    &entry.id,
                    "cached_input_read_price",
                )?;

                Ok(crate::gateway::provider_catalog::CatalogModel {
                    id: entry.id,
                    provider_id: entry.provider_id,
                    model_type: entry.model_type,
                    context_window: entry.context_window,
                    max_output_tokens: entry.max_output_tokens,
                    supported_features: entry.supported_features,
                    input_token_price,
                    output_token_price,
                    cached_input_read_price,
                    parameter_overrides: entry.parameter_overrides,
                    removed_params: entry.removed_params,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Some(crate::gateway::provider_catalog::CatalogSnapshot {
            version: catalog_version,
            providers: Vec::new(),
            models,
            synced_at: Some(Utc::now()),
        })
    } else {
        None
    };

    build_pulled_gateway_config(
        gateway_id,
        runtime_registration_id,
        region_key,
        publication_catalog,
        routing_compatibility,
        peer_gateways,
        relay_hmac_secret,
        catalog_snapshot,
        yaml,
    )
}

#[derive(Debug)]
pub(crate) struct PulledGatewayConfig {
    pub(crate) gateway_id: Option<String>,
    pub(crate) runtime_registration_id: Option<String>,
    pub(crate) region_key: Option<String>,
    pub(crate) publication_catalog:
        Vec<crate::runtime::ConnectedGatewayPublicationCatalogDescriptor>,
    pub(crate) routing_compatibility:
        Vec<crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor>,
    pub(crate) peer_gateways: Vec<crate::runtime::PeerGatewayDescriptor>,
    pub(crate) relay_hmac_secret: Option<String>,
    pub(crate) catalog_snapshot: Option<crate::gateway::provider_catalog::CatalogSnapshot>,
    pub(crate) loaded_config: Option<crate::gateway::declarative_config::LoadedDeclarativeConfig>,
}

pub(crate) const CONNECTED_READ_MODEL_REFRESH_INTERVAL_SECS: u64 = 30;
pub(crate) const CONNECTED_READ_MODEL_DEFAULT_STALE_AFTER_SECS: i64 = 90;
pub(crate) const CONNECTED_READ_MODEL_NEGATIVE_CACHE_TTL_SECS: i64 = 15;
pub(crate) const CONNECTED_READ_MODEL_NEGATIVE_CACHE_MAX_ENTRIES: usize = 256;
pub(crate) const CONNECTED_READ_MODEL_HOST_SHARD_PREFIX_LEN: usize = 2;

#[derive(Clone, Debug)]
pub(crate) struct AuthVerificationMaterial {
    pub(crate) jwks_keys: Vec<serde_json::Value>,
    pub(crate) refreshed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub(crate) struct FamilyMetadataEntry {
    pub(crate) family_key: String,
    pub(crate) lifecycle_state: String,
    pub(crate) default_locality_mode: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RegistryMetadataFeed {
    pub(crate) families: Vec<FamilyMetadataEntry>,
}

#[derive(Clone, Debug)]
pub(crate) struct RegionHealthEntry {
    pub(crate) region_key: String,
    pub(crate) healthy: bool,
    pub(crate) load_percent: Option<u8>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CapacityHealthFeed {
    pub(crate) cell_health: Vec<RegionHealthEntry>,
}

pub(crate) fn routing_compatibility_index_key(
    publication_key: &str,
    active_revision_id: Option<&str>,
) -> String {
    format!(
        "{publication_key}\u{0}{}",
        active_revision_id.unwrap_or_default()
    )
}

pub(crate) fn managed_public_endpoint_host_shard_key(host: &str) -> String {
    let trimmed = host.trim().to_ascii_lowercase();
    let prefix: String = trimmed
        .chars()
        .filter(|value| value.is_ascii_alphanumeric())
        .take(CONNECTED_READ_MODEL_HOST_SHARD_PREFIX_LEN)
        .collect();
    if prefix.is_empty() {
        "_".to_string()
    } else {
        prefix
    }
}

pub(crate) fn build_managed_public_endpoint_catalog_shards(
    publication_catalog: &[crate::runtime::ConnectedGatewayPublicationCatalogDescriptor],
) -> HashMap<String, Vec<crate::runtime::ConnectedGatewayPublicationCatalogDescriptor>> {
    let mut shards = HashMap::new();
    for publication in publication_catalog {
        let Some(host) = publication
            .published_hostname
            .as_deref()
            .and_then(normalize_managed_public_endpoint_host)
        else {
            continue;
        };
        shards
            .entry(managed_public_endpoint_host_shard_key(&host))
            .or_insert_with(Vec::new)
            .push(publication.clone());
    }
    shards
}

pub(crate) fn build_routing_compatibility_index(
    routing_compatibility: &[crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor],
) -> HashMap<String, crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor> {
    let mut index = HashMap::new();
    for descriptor in routing_compatibility {
        index.insert(
            routing_compatibility_index_key(
                &descriptor.publication_key,
                descriptor.active_revision_id.as_deref(),
            ),
            descriptor.clone(),
        );
    }
    index
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ConnectedGatewayReadModelState {
    pub(crate) region_key: Option<String>,
    pub(crate) publication_catalog:
        Vec<crate::runtime::ConnectedGatewayPublicationCatalogDescriptor>,
    pub(crate) publication_catalog_shards:
        HashMap<String, Vec<crate::runtime::ConnectedGatewayPublicationCatalogDescriptor>>,
    pub(crate) publication_catalog_last_successful_refresh_at: Option<DateTime<Utc>>,
    pub(crate) publication_catalog_last_refresh_error: Option<String>,
    pub(crate) routing_compatibility:
        Vec<crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor>,
    pub(crate) routing_compatibility_index:
        HashMap<String, crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor>,
    pub(crate) routing_compatibility_last_successful_refresh_at: Option<DateTime<Utc>>,
    pub(crate) routing_compatibility_last_refresh_error: Option<String>,
    pub(crate) auth_verification_material: Option<AuthVerificationMaterial>,
    pub(crate) auth_verification_material_last_successful_refresh_at: Option<DateTime<Utc>>,
    pub(crate) auth_verification_material_last_refresh_error: Option<String>,
    pub(crate) registry_metadata: RegistryMetadataFeed,
    pub(crate) registry_metadata_last_successful_refresh_at: Option<DateTime<Utc>>,
    pub(crate) registry_metadata_last_refresh_error: Option<String>,
    pub(crate) capacity_health: CapacityHealthFeed,
    pub(crate) capacity_health_last_successful_refresh_at: Option<DateTime<Utc>>,
    pub(crate) capacity_health_last_refresh_error: Option<String>,
    pub(crate) peer_gateways: Vec<crate::runtime::PeerGatewayDescriptor>,
    pub(crate) relay_hmac_secret: Option<String>,
    pub(crate) stale_after_secs: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectedGatewayReadModelSnapshot {
    pub(crate) region_key: Option<String>,
    pub(crate) publication_catalog:
        Vec<crate::runtime::ConnectedGatewayPublicationCatalogDescriptor>,
    pub(crate) publication_catalog_shards:
        HashMap<String, Vec<crate::runtime::ConnectedGatewayPublicationCatalogDescriptor>>,
    pub(crate) publication_catalog_last_successful_refresh_at: Option<DateTime<Utc>>,
    pub(crate) publication_catalog_last_refresh_error: Option<String>,
    pub(crate) routing_compatibility:
        Vec<crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor>,
    pub(crate) routing_compatibility_index:
        HashMap<String, crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor>,
    pub(crate) routing_compatibility_last_successful_refresh_at: Option<DateTime<Utc>>,
    pub(crate) routing_compatibility_last_refresh_error: Option<String>,
    pub(crate) auth_verification_material: Option<AuthVerificationMaterial>,
    pub(crate) auth_verification_material_last_successful_refresh_at: Option<DateTime<Utc>>,
    pub(crate) auth_verification_material_last_refresh_error: Option<String>,
    pub(crate) registry_metadata: RegistryMetadataFeed,
    pub(crate) registry_metadata_last_successful_refresh_at: Option<DateTime<Utc>>,
    pub(crate) registry_metadata_last_refresh_error: Option<String>,
    pub(crate) capacity_health: CapacityHealthFeed,
    pub(crate) capacity_health_last_successful_refresh_at: Option<DateTime<Utc>>,
    pub(crate) capacity_health_last_refresh_error: Option<String>,
    pub(crate) peer_gateways: Vec<crate::runtime::PeerGatewayDescriptor>,
    pub(crate) relay_hmac_secret: Option<String>,
    pub(crate) managed_public_endpoint_negative_cache:
        Arc<std::sync::Mutex<HashMap<String, DateTime<Utc>>>>,
    pub(crate) stale_after_secs: i64,
}

impl ConnectedGatewayReadModelSnapshot {
    pub(crate) fn peer_relay_endpoints_for_agent(&self, agent_id: &str) -> Vec<String> {
        crate::gateway::relay::filter_cell_local_peers(
            &self.peer_gateways,
            agent_id,
            self.region_key.as_deref(),
        )
    }
    pub(crate) fn feed_age_seconds(
        refreshed_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Option<i64> {
        refreshed_at.map(|value| (now - value).num_seconds().max(0))
    }

    pub(crate) fn stale_after_secs(&self) -> i64 {
        self.stale_after_secs
    }

    pub(crate) fn feed_is_stale_with_budget(
        refreshed_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        stale_after_secs: i64,
    ) -> bool {
        Self::feed_age_seconds(refreshed_at, now)
            .map(|age_secs| age_secs > stale_after_secs)
            .unwrap_or(true)
    }

    pub(crate) fn feed_status_with_budget(
        refreshed_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        stale_after_secs: i64,
    ) -> &'static str {
        if Self::feed_is_stale_with_budget(refreshed_at, now, stale_after_secs) {
            "stale"
        } else {
            "fresh"
        }
    }

    pub(crate) fn publication_catalog_age_seconds(&self, now: DateTime<Utc>) -> Option<i64> {
        Self::feed_age_seconds(self.publication_catalog_last_successful_refresh_at, now)
    }

    pub(crate) fn publication_catalog_is_stale(&self, now: DateTime<Utc>) -> bool {
        Self::feed_is_stale_with_budget(
            self.publication_catalog_last_successful_refresh_at,
            now,
            self.stale_after_secs,
        )
    }

    pub(crate) fn publication_catalog_status(&self, now: DateTime<Utc>) -> &'static str {
        Self::feed_status_with_budget(
            self.publication_catalog_last_successful_refresh_at,
            now,
            self.stale_after_secs,
        )
    }

    pub(crate) fn routing_compatibility_age_seconds(&self, now: DateTime<Utc>) -> Option<i64> {
        Self::feed_age_seconds(self.routing_compatibility_last_successful_refresh_at, now)
    }

    pub(crate) fn routing_compatibility_is_stale(&self, now: DateTime<Utc>) -> bool {
        Self::feed_is_stale_with_budget(
            self.routing_compatibility_last_successful_refresh_at,
            now,
            self.stale_after_secs,
        )
    }

    pub(crate) fn routing_compatibility_status(&self, now: DateTime<Utc>) -> &'static str {
        Self::feed_status_with_budget(
            self.routing_compatibility_last_successful_refresh_at,
            now,
            self.stale_after_secs,
        )
    }

    pub(crate) fn auth_verification_material_is_stale(&self, now: DateTime<Utc>) -> bool {
        Self::feed_is_stale_with_budget(
            self.auth_verification_material_last_successful_refresh_at,
            now,
            self.stale_after_secs,
        )
    }

    pub(crate) fn auth_verification_material_status(&self, now: DateTime<Utc>) -> &'static str {
        Self::feed_status_with_budget(
            self.auth_verification_material_last_successful_refresh_at,
            now,
            self.stale_after_secs,
        )
    }

    pub(crate) fn registry_metadata_is_stale(&self, now: DateTime<Utc>) -> bool {
        Self::feed_is_stale_with_budget(
            self.registry_metadata_last_successful_refresh_at,
            now,
            self.stale_after_secs,
        )
    }

    pub(crate) fn registry_metadata_status(&self, now: DateTime<Utc>) -> &'static str {
        Self::feed_status_with_budget(
            self.registry_metadata_last_successful_refresh_at,
            now,
            self.stale_after_secs,
        )
    }

    pub(crate) fn capacity_health_is_stale(&self, now: DateTime<Utc>) -> bool {
        Self::feed_is_stale_with_budget(
            self.capacity_health_last_successful_refresh_at,
            now,
            self.stale_after_secs,
        )
    }

    pub(crate) fn capacity_health_status(&self, now: DateTime<Utc>) -> &'static str {
        Self::feed_status_with_budget(
            self.capacity_health_last_successful_refresh_at,
            now,
            self.stale_after_secs,
        )
    }

    pub(crate) fn routing_compatibility_for_publication(
        &self,
        publication: &crate::runtime::ConnectedGatewayPublicationCatalogDescriptor,
    ) -> Option<&crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor> {
        self.routing_compatibility_index
            .get(&routing_compatibility_index_key(
                &publication.publication_key,
                publication.active_revision_id.as_deref(),
            ))
    }

    pub(crate) fn cached_negative_lookup_contains(
        &self,
        requested_host: &str,
        now: DateTime<Utc>,
    ) -> bool {
        #[allow(clippy::expect_used)]
        let mut guard = self
            .managed_public_endpoint_negative_cache
            .lock()
            .expect("managed public endpoint negative cache lock");
        guard.retain(|_, inserted_at| {
            (now - *inserted_at).num_seconds() <= CONNECTED_READ_MODEL_NEGATIVE_CACHE_TTL_SECS
        });
        guard.contains_key(requested_host)
    }

    pub(crate) fn record_negative_lookup(&self, requested_host: &str, now: DateTime<Utc>) {
        #[allow(clippy::expect_used)]
        let mut guard = self
            .managed_public_endpoint_negative_cache
            .lock()
            .expect("managed public endpoint negative cache lock");
        guard.retain(|_, inserted_at| {
            (now - *inserted_at).num_seconds() <= CONNECTED_READ_MODEL_NEGATIVE_CACHE_TTL_SECS
        });
        if guard.len() >= CONNECTED_READ_MODEL_NEGATIVE_CACHE_MAX_ENTRIES {
            if let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, inserted_at)| *inserted_at)
                .map(|(host, _)| host.clone())
            {
                guard.remove(&oldest_key);
            }
        }
        guard.insert(requested_host.to_string(), now);
    }
}

#[derive(Clone, Debug, Default)]
pub struct SharedConnectedGatewayReadModel {
    pub(crate) inner: Arc<RwLock<ConnectedGatewayReadModelState>>,
    pub(crate) managed_public_endpoint_negative_cache:
        Arc<std::sync::Mutex<HashMap<String, DateTime<Utc>>>>,
}

impl SharedConnectedGatewayReadModel {
    pub(crate) fn new(
        region_key: Option<String>,
        publication_catalog: Vec<crate::runtime::ConnectedGatewayPublicationCatalogDescriptor>,
        publication_catalog_last_successful_refresh_at: Option<DateTime<Utc>>,
        routing_compatibility: Vec<crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor>,
        routing_compatibility_last_successful_refresh_at: Option<DateTime<Utc>>,
    ) -> Self {
        let publication_catalog_shards =
            build_managed_public_endpoint_catalog_shards(&publication_catalog);
        let routing_compatibility_index = build_routing_compatibility_index(&routing_compatibility);
        Self {
            inner: Arc::new(RwLock::new(ConnectedGatewayReadModelState {
                region_key,
                publication_catalog,
                publication_catalog_shards,
                publication_catalog_last_successful_refresh_at,
                publication_catalog_last_refresh_error: None,
                routing_compatibility,
                routing_compatibility_index,
                routing_compatibility_last_successful_refresh_at,
                routing_compatibility_last_refresh_error: None,
                auth_verification_material: None,
                auth_verification_material_last_successful_refresh_at: None,
                auth_verification_material_last_refresh_error: None,
                registry_metadata: RegistryMetadataFeed::default(),
                registry_metadata_last_successful_refresh_at: None,
                registry_metadata_last_refresh_error: None,
                capacity_health: CapacityHealthFeed::default(),
                capacity_health_last_successful_refresh_at: None,
                capacity_health_last_refresh_error: None,
                peer_gateways: Vec::new(),
                relay_hmac_secret: None,
                stale_after_secs: CONNECTED_READ_MODEL_DEFAULT_STALE_AFTER_SECS,
            })),
            managed_public_endpoint_negative_cache: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn set_stale_after_secs(&self, secs: i64) {
        #[allow(clippy::expect_used)]
        let mut guard = self
            .inner
            .write()
            .expect("connected gateway read model lock");
        guard.stale_after_secs = secs;
    }

    pub(crate) fn snapshot(&self) -> ConnectedGatewayReadModelSnapshot {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let snapshot = self
            .inner
            .read()
            .expect("connected gateway read model lock");
        ConnectedGatewayReadModelSnapshot {
            region_key: snapshot.region_key.clone(),
            publication_catalog: snapshot.publication_catalog.clone(),
            publication_catalog_shards: snapshot.publication_catalog_shards.clone(),
            publication_catalog_last_successful_refresh_at: snapshot
                .publication_catalog_last_successful_refresh_at,
            publication_catalog_last_refresh_error: snapshot
                .publication_catalog_last_refresh_error
                .clone(),
            routing_compatibility: snapshot.routing_compatibility.clone(),
            routing_compatibility_index: snapshot.routing_compatibility_index.clone(),
            routing_compatibility_last_successful_refresh_at: snapshot
                .routing_compatibility_last_successful_refresh_at,
            routing_compatibility_last_refresh_error: snapshot
                .routing_compatibility_last_refresh_error
                .clone(),
            auth_verification_material: snapshot.auth_verification_material.clone(),
            auth_verification_material_last_successful_refresh_at: snapshot
                .auth_verification_material_last_successful_refresh_at,
            auth_verification_material_last_refresh_error: snapshot
                .auth_verification_material_last_refresh_error
                .clone(),
            registry_metadata: snapshot.registry_metadata.clone(),
            registry_metadata_last_successful_refresh_at: snapshot
                .registry_metadata_last_successful_refresh_at,
            registry_metadata_last_refresh_error: snapshot
                .registry_metadata_last_refresh_error
                .clone(),
            capacity_health: snapshot.capacity_health.clone(),
            capacity_health_last_successful_refresh_at: snapshot
                .capacity_health_last_successful_refresh_at,
            capacity_health_last_refresh_error: snapshot.capacity_health_last_refresh_error.clone(),
            peer_gateways: snapshot.peer_gateways.clone(),
            relay_hmac_secret: snapshot.relay_hmac_secret.clone(),
            managed_public_endpoint_negative_cache: self
                .managed_public_endpoint_negative_cache
                .clone(),
            stale_after_secs: snapshot.stale_after_secs,
        }
    }

    #[doc(hidden)]
    pub fn record_peer_gateway_refresh(
        &self,
        peer_gateways: Vec<crate::runtime::PeerGatewayDescriptor>,
        refreshed_at: DateTime<Utc>,
    ) {
        let snapshot = self.snapshot();
        self.record_success(
            snapshot.region_key,
            snapshot.publication_catalog,
            snapshot.routing_compatibility,
            peer_gateways,
            snapshot.relay_hmac_secret,
            refreshed_at,
        );
    }

    pub(crate) fn record_success(
        &self,
        region_key: Option<String>,
        publication_catalog: Vec<crate::runtime::ConnectedGatewayPublicationCatalogDescriptor>,
        routing_compatibility: Vec<crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor>,
        peer_gateways: Vec<crate::runtime::PeerGatewayDescriptor>,
        relay_hmac_secret: Option<String>,
        refreshed_at: DateTime<Utc>,
    ) {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut guard = self
            .inner
            .write()
            .expect("connected gateway read model lock");
        let publication_catalog_shards =
            build_managed_public_endpoint_catalog_shards(&publication_catalog);
        let routing_compatibility_index = build_routing_compatibility_index(&routing_compatibility);
        guard.region_key = region_key;
        guard.publication_catalog = publication_catalog;
        guard.publication_catalog_shards = publication_catalog_shards;
        guard.publication_catalog_last_successful_refresh_at = Some(refreshed_at);
        guard.publication_catalog_last_refresh_error = None;
        guard.routing_compatibility = routing_compatibility;
        guard.routing_compatibility_index = routing_compatibility_index;
        guard.routing_compatibility_last_successful_refresh_at = Some(refreshed_at);
        guard.routing_compatibility_last_refresh_error = None;
        guard.auth_verification_material_last_successful_refresh_at = Some(refreshed_at);
        guard.auth_verification_material_last_refresh_error = None;
        guard.registry_metadata_last_successful_refresh_at = Some(refreshed_at);
        guard.registry_metadata_last_refresh_error = None;
        guard.capacity_health_last_successful_refresh_at = Some(refreshed_at);
        guard.capacity_health_last_refresh_error = None;
        guard.peer_gateways = peer_gateways;
        guard.relay_hmac_secret = relay_hmac_secret;
        #[allow(clippy::expect_used)]
        let mut negative_cache = self
            .managed_public_endpoint_negative_cache
            .lock()
            .expect("managed public endpoint negative cache lock");
        negative_cache.clear();
    }

    pub(crate) fn record_failure(&self, error: impl Into<String>) {
        // SAFETY: lock poisoning indicates a panic in another thread; crashing is correct behavior
        #[allow(clippy::expect_used)]
        let mut guard = self
            .inner
            .write()
            .expect("connected gateway read model lock");
        let error = error.into();
        guard.publication_catalog_last_refresh_error = Some(error.clone());
        guard.routing_compatibility_last_refresh_error = Some(error.clone());
        guard.auth_verification_material_last_refresh_error = Some(error.clone());
        guard.registry_metadata_last_refresh_error = Some(error.clone());
        guard.capacity_health_last_refresh_error = Some(error);
    }
}

pub(crate) fn build_pulled_gateway_config(
    gateway_id: Option<String>,
    runtime_registration_id: Option<String>,
    region_key: Option<String>,
    publication_catalog: Vec<crate::runtime::ConnectedGatewayPublicationCatalogDescriptor>,
    routing_compatibility: Vec<crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor>,
    peer_gateways: Vec<crate::runtime::PeerGatewayDescriptor>,
    relay_hmac_secret: Option<String>,
    catalog_snapshot: Option<crate::gateway::provider_catalog::CatalogSnapshot>,
    yaml: Option<String>,
) -> anyhow::Result<PulledGatewayConfig> {
    let loaded_config = match yaml {
        Some(yaml) if !yaml.trim().is_empty() => Some(
            crate::gateway::declarative_config::LoadedDeclarativeConfig::from_bytes(
                yaml.as_bytes(),
            )?,
        ),
        _ => None,
    };

    Ok(PulledGatewayConfig {
        gateway_id: normalize_optional_owned(gateway_id),
        runtime_registration_id: normalize_optional_owned(runtime_registration_id),
        region_key: normalize_optional_owned(region_key),
        publication_catalog,
        routing_compatibility,
        peer_gateways,
        relay_hmac_secret,
        catalog_snapshot,
        loaded_config,
    })
}

pub(crate) fn normalize_optional_owned(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn waiting_connected_config(
    local_hosted_gateway: &Option<crate::gateway::declarative_config::HostedGatewayRuntimeConfig>,
) -> crate::gateway::declarative_config::LoadedDeclarativeConfig {
    let mut waiting_config = LoadedDeclarativeConfig::empty();
    waiting_config.hosted_gateway = local_hosted_gateway.clone();
    waiting_config
}

pub(crate) fn apply_connected_control_plane_pull(
    config: &mut crate::runtime::RuntimeInstanceConfig,
    local_hosted_gateway: &Option<crate::gateway::declarative_config::HostedGatewayRuntimeConfig>,
    pulled: PulledGatewayConfig,
) -> bool {
    if config.gateway_id.is_none() {
        config.gateway_id = pulled.gateway_id;
    }
    if config.runtime_registration_id.is_none() {
        config.runtime_registration_id = pulled.runtime_registration_id;
    }
    if config.region_key.is_none() {
        config.region_key = pulled.region_key;
    }
    if config.publication_catalog.is_empty() {
        config.publication_catalog = pulled.publication_catalog;
    }
    if config.routing_compatibility.is_empty() {
        config.routing_compatibility = pulled.routing_compatibility;
    }

    match pulled.loaded_config {
        Some(mut loaded_config) => {
            if loaded_config.hosted_gateway.is_none() {
                loaded_config.hosted_gateway = local_hosted_gateway.clone();
            }
            config.loaded_config = loaded_config;
            true
        }
        None => {
            config.loaded_config = waiting_connected_config(local_hosted_gateway);
            false
        }
    }
}

// ── Auto-registration helpers ────────────────────────────────────────────

pub(crate) const REGISTRATION_CACHE_PATH: &str = "/tmp/verdictan/registration.json";

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct RegistrationCache {
    pub(crate) runtime_registration_id: String,
    pub(crate) gateway_id: String,
}

#[derive(Debug)]
pub(crate) enum RegisterError {
    Conflict,
    Other(String),
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict => write!(f, "gateway_id already exists (409 Conflict)"),
            Self::Other(msg) => f.write_str(msg),
        }
    }
}

pub(crate) fn derive_gateway_id(agent_name: Option<&str>) -> String {
    match agent_name {
        Some(name) => {
            let sanitized: String = name
                .trim()
                .to_lowercase()
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect();
            format!("{sanitized}-gw")
        }
        None => {
            let host = std::env::var("HOSTNAME")
                .ok()
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "unknown".to_string());
            format!("{}-gw", host.to_lowercase())
        }
    }
}

pub(crate) fn short_hostname_hash() -> String {
    use std::hash::{Hash, Hasher};
    let host = std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    host.hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
}

pub(crate) fn load_registration_cache() -> Option<RegistrationCache> {
    let data = std::fs::read_to_string(REGISTRATION_CACHE_PATH).ok()?;
    serde_json::from_str(&data).ok()
}

pub(crate) fn persist_registration_cache(runtime_registration_id: &str, gateway_id: &str) {
    let cache = RegistrationCache {
        runtime_registration_id: runtime_registration_id.to_string(),
        gateway_id: gateway_id.to_string(),
    };
    if let Some(parent) = std::path::Path::new(REGISTRATION_CACHE_PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(&cache) {
        Ok(json) => {
            if let Err(e) = std::fs::write(REGISTRATION_CACHE_PATH, json) {
                tracing::warn!(
                    error = %e,
                    "connected-mode startup: failed to persist registration cache"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "connected-mode startup: failed to serialize registration cache"
            );
        }
    }
}

pub(crate) async fn try_register_gateway(
    sink: &EventSink,
    gateway_id: &str,
    name: &str,
    agent_name: Option<&str>,
) -> Result<String, RegisterError> {
    let url = format!("{}/v1/gateways", sink.base_url);
    let mut body = serde_json::json!({
        "gateway_id": gateway_id,
        "name": name,
    });
    if let Some(an) = agent_name.filter(|s| !s.is_empty()) {
        body["agent_name"] = serde_json::Value::String(an.to_string());
    }

    let response = sink
        .client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| RegisterError::Other(format!("network error: {e}")))?;

    let status = response.status();
    if status == reqwest::StatusCode::CONFLICT {
        return Err(RegisterError::Conflict);
    }
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();
        return Err(RegisterError::Other(format!(
            "registration failed: status={status} body={body_text}"
        )));
    }

    #[derive(serde::Deserialize)]
    struct RegisterResponse {
        pub(crate) runtime_registration_id: Option<String>,
        pub(crate) id: Option<String>,
    }

    let parsed: RegisterResponse = response
        .json()
        .await
        .map_err(|e| RegisterError::Other(format!("failed to parse registration response: {e}")))?;

    parsed.runtime_registration_id.or(parsed.id).ok_or_else(|| {
        RegisterError::Other("registration response missing runtime_registration_id".to_string())
    })
}

/// Attempt to auto-register this gateway instance with the control plane.
///
/// Checks on-disk cache first, then POSTs to the gateways API. On a 409
/// conflict the call is retried once with a hostname-derived suffix appended
/// to the `gateway_id`. Returns `None` when registration cannot be completed
/// so the caller can fall back to degraded (waiting) mode.
pub(crate) async fn auto_register_gateway(
    sink: &EventSink,
    agent_name: Option<&str>,
) -> Option<String> {
    if let Some(cached) = load_registration_cache() {
        tracing::info!(
            runtime_registration_id = %cached.runtime_registration_id,
            gateway_id = %cached.gateway_id,
            "connected-mode startup: using cached gateway registration"
        );
        return Some(cached.runtime_registration_id);
    }

    let gateway_id = derive_gateway_id(agent_name);
    let display_name = match agent_name {
        Some(name) => format!("{name} Gateway"),
        None => "Auto-registered Gateway".to_string(),
    };

    match try_register_gateway(sink, &gateway_id, &display_name, agent_name).await {
        Ok(id) => {
            persist_registration_cache(&id, &gateway_id);
            Some(id)
        }
        Err(RegisterError::Conflict) => {
            let suffix = short_hostname_hash();
            let retry_id = format!("{gateway_id}-{suffix}");
            let retry_name = format!("{display_name} ({suffix})");
            tracing::info!(
                gateway_id = %retry_id,
                "connected-mode startup: gateway_id conflict, retrying with hostname suffix"
            );
            match try_register_gateway(sink, &retry_id, &retry_name, agent_name).await {
                Ok(id) => {
                    persist_registration_cache(&id, &retry_id);
                    Some(id)
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "connected-mode startup: auto-registration retry failed"
                    );
                    None
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "connected-mode startup: auto-registration failed"
            );
            None
        }
    }
}

pub(crate) async fn refresh_connected_read_model_once(
    sink: &EventSink,
    runtime_registration_id: &str,
    local_hosted_gateway: &Option<crate::gateway::declarative_config::HostedGatewayRuntimeConfig>,
    active_config: &SharedGatewayConfig,
    connected_read_model: &SharedConnectedGatewayReadModel,
    catalog_resolver: &crate::gateway::provider_catalog::CatalogBackedProviderResolver,
    reload_guard: &Arc<tokio::sync::Mutex<()>>,
) -> anyhow::Result<()> {
    let pulled = match pull_config_from_api(sink, Some(runtime_registration_id)).await {
        Ok(pulled) => pulled,
        Err(error) => {
            connected_read_model.record_failure(error.to_string());
            return Err(error);
        }
    };
    let PulledGatewayConfig {
        region_key,
        publication_catalog,
        routing_compatibility,
        peer_gateways,
        relay_hmac_secret,
        catalog_snapshot,
        loaded_config,
        ..
    } = pulled;

    if let Some(catalog_snapshot) = catalog_snapshot {
        catalog_resolver.update_snapshot(catalog_snapshot).await;
    }

    if let Some(mut loaded_config) = loaded_config {
        if loaded_config.hosted_gateway.is_none() {
            loaded_config.hosted_gateway = local_hosted_gateway.clone();
        }
        let event_sink = Some(sink.clone());
        if let Err(error) = crate::gateway::secret_resolver::resolve_hosted_secret_key_refs(
            &event_sink,
            &mut loaded_config,
        )
        .await
        {
            tracing::warn!(
                runtime_registration_id = %runtime_registration_id,
                error = %error,
                "connected read model refresh: failed to resolve secret refs for refreshed config"
            );
        }

        // Serialize with admin-initiated reloads so requests do not observe a
        // half-applied config publication while the refreshed read model is
        // taking effect.
        let _reload_lock = reload_guard.lock().await;
        let cb_snapshot = active_config
            .snapshot()
            .provider_registry
            .as_ref()
            .and_then(|registry| registry.circuit_breaker_manager.as_ref())
            .map(|manager| manager.snapshot());
        if let Some(ref snapshot) = cb_snapshot {
            if let Some(manager) = loaded_config
                .provider_registry
                .as_ref()
                .and_then(|registry| registry.circuit_breaker_manager.as_ref())
            {
                manager.restore(snapshot);
            }
        }
        active_config.replace(loaded_config.clone());
        tracing::info!(
            runtime_registration_id = %runtime_registration_id,
            config_version = %loaded_config.config_version,
            config_sha256 = %loaded_config.config_sha256,
            "connected read model refresh applied updated config"
        );
    }

    connected_read_model.record_success(
        region_key,
        publication_catalog,
        routing_compatibility,
        peer_gateways,
        relay_hmac_secret,
        Utc::now(),
    );
    Ok(())
}

pub async fn spawn_instance(
    mut config: crate::runtime::RuntimeInstanceConfig,
) -> Result<GatewayHandle, CliError> {
    if config.upstream.trim().is_empty() {
        return Err(CliError::user("upstream url is empty"));
    }

    let event_sink = match config.event_sink.clone() {
        Some(cfg) => {
            // Capture credentials before consuming config so we can configure OAuth persistence.
            let api_base_url = cfg.base_url.clone();
            let api_token = cfg.api_token.clone();
            crate::gateway::oauth_token_store::OAuthTokenStore::global()
                .configure_api_persistence(api_base_url, api_token);
            Some(EventSink::from_config(cfg)?)
        }
        None => None,
    };

    // Phase 9: apply logging suppression config to the event sink.
    let event_sink = event_sink.map(|sink| {
        let redact = config
            .loaded_config
            .provider_registry
            .as_ref()
            .map(|r| r.logging.redact_message_bodies)
            .unwrap_or(false);
        sink.with_redact_bodies(redact)
    });

    // Start the durable WAL delivery worker for connected event forwarding.
    spawn_wal_delivery_worker(event_sink.as_ref());

    // ── Phase 40: Log effective region at gateway startup ──────────────────
    if let Some(ref region) = config.loaded_config.region {
        tracing::info!(region = %region, "gateway operating region (from declarative config)");
    } else if let Ok(env_region) = std::env::var("VERDICTAN_REGION") {
        let env_region = env_region.trim();
        if !env_region.is_empty() {
            tracing::info!(region = %env_region, "gateway operating region (from VERDICTAN_REGION env)");
        }
    }

    let local_hosted_gateway = config.loaded_config.hosted_gateway.clone();
    let catalog_resolver = crate::gateway::provider_catalog::CatalogBackedProviderResolver::new();
    let mut connected_publication_catalog_refreshed_at = None;
    let mut connected_routing_compatibility_refreshed_at = None;
    let mut connected_routing_compatibility = config.routing_compatibility.clone();
    let mut connected_startup_peer_gateways = Vec::new();
    let mut connected_startup_relay_hmac_secret = None;
    let mut connected_startup_region_key = config.region_key.clone();

    // ── Connected-mode config pull ─────────────────────────────────────────
    //
    // Connected gateways wait for a control-plane deployment instead of
    // serving any baked-in local provider registry.
    if config.connected_mode {
        if let Some(ref sink) = event_sink {
            let runtime_registration_id_from_env =
                optional_env("VERDICTAN_RUNTIME_REGISTRATION_ID");
            let mut runtime_registration_id = config
                .runtime_registration_id
                .clone()
                .or(runtime_registration_id_from_env);

            if runtime_registration_id.is_none() {
                let agent_name = optional_env("VERDICTAN_AGENT_NAME");
                match auto_register_gateway(sink, agent_name.as_deref()).await {
                    Some(registered_id) => {
                        tracing::info!(
                            runtime_registration_id = %registered_id,
                            "connected-mode startup: auto-registered with the control plane"
                        );
                        runtime_registration_id = Some(registered_id);
                    }
                    None => {
                        tracing::warn!(
                            "connected-mode startup: auto-registration unavailable, waiting for control-plane configuration"
                        );
                        config.loaded_config = waiting_connected_config(&local_hosted_gateway);
                    }
                }
            }

            if let Some(runtime_registration_id) = runtime_registration_id {
                let bootstrap_loaded_config = config.loaded_config.clone();
                match pull_config_from_api(sink, Some(runtime_registration_id.as_str())).await {
                    Ok(pulled) => {
                        let refreshed_at = Utc::now();
                        connected_publication_catalog_refreshed_at = Some(refreshed_at);
                        connected_routing_compatibility_refreshed_at = Some(refreshed_at);
                        connected_routing_compatibility = pulled.routing_compatibility.clone();
                        connected_startup_region_key =
                            pulled.region_key.clone().or(connected_startup_region_key);
                        connected_startup_peer_gateways = pulled.peer_gateways.clone();
                        connected_startup_relay_hmac_secret = pulled.relay_hmac_secret.clone();
                        if let Some(catalog_snapshot) = pulled.catalog_snapshot.clone() {
                            catalog_resolver.update_snapshot(catalog_snapshot).await;
                        }
                        let has_assigned_config = pulled.loaded_config.is_some();
                        let requested_runtime_registration_id = runtime_registration_id.as_str();
                        if let Some(ref gateway_id) = pulled.gateway_id {
                            tracing::info!(
                                requested_runtime_registration_id = %requested_runtime_registration_id,
                                gateway_id = %gateway_id,
                                "connected-mode startup: resolved control-plane gateway identity"
                            );
                        }
                        let resolved_runtime_registration_id = pulled
                            .runtime_registration_id
                            .clone()
                            .or_else(|| Some(runtime_registration_id.clone()))
                            .unwrap_or_else(|| "<unresolved>".to_string());
                        let assigned_config_loaded = apply_connected_control_plane_pull(
                            &mut config,
                            &local_hosted_gateway,
                            pulled,
                        );
                        debug_assert_eq!(assigned_config_loaded, has_assigned_config);

                        if has_assigned_config {
                            tracing::info!(
                                runtime_registration_id = %resolved_runtime_registration_id,
                                "connected-mode startup: loaded config from control-plane"
                            );
                            if let Err(error) =
                                crate::gateway::secret_resolver::resolve_hosted_secret_key_refs(
                                    &event_sink,
                                    &mut config.loaded_config,
                                )
                                .await
                            {
                                tracing::warn!(
                                    runtime_registration_id = %resolved_runtime_registration_id,
                                    error = %error,
                                    "connected-mode startup: failed to resolve secret refs for deployed config"
                                );
                            }
                        } else {
                            tracing::info!(
                                runtime_registration_id = %resolved_runtime_registration_id,
                                "connected-mode startup: no config assigned to this gateway; waiting for an API deployment"
                            );
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            requested_runtime_registration_id = %runtime_registration_id,
                            error = %error,
                            "connected-mode startup: config pull failed; waiting for a control-plane deployment"
                        );
                        if bootstrap_loaded_config.raw_yaml.trim().is_empty() {
                            config.loaded_config = waiting_connected_config(&local_hosted_gateway);
                        } else {
                            config.loaded_config = bootstrap_loaded_config;
                        }
                    }
                }
            }
        } else {
            tracing::warn!(
                "connected-mode startup: control-plane connection is unavailable, waiting for configuration"
            );
            config.loaded_config = waiting_connected_config(&local_hosted_gateway);
        }
    } else {
        // Resolve secret_key_ref.store values from the org-scoped config
        // variable store before traffic is served. This is a no-op when
        // event_sink is None or no targets carry secret_key_ref.store.
        crate::gateway::secret_resolver::resolve_hosted_secret_key_refs(
            &event_sink,
            &mut config.loaded_config,
        )
        .await
        .map_err(|error| {
            crate::error::CliError::user(format!("failed to prepare gateway config: {error}"))
        })?;
    }

    log_provider_target_startup_statuses(config.connected_mode, &config.loaded_config);

    let api_base_url = optional_env("VERDICTAN_API_URL")
        .or_else(|| event_sink.as_ref().map(|sink| sink.base_url.clone()));
    let control_plane_available = api_base_url.is_some();
    let agent_context_service = build_agent_context_service(&event_sink);
    let history_service = build_history_service(&event_sink, &config.loaded_config);
    if history_service.is_some() {
        tracing::info!(history_enabled = true, "gateway history capture status");
    } else {
        tracing::warn!(
            "Gateway history capture is disabled. \
             Set 'history.enabled: true' in gateway config to enable conversation tracking."
        );
    }

    let upstream_auth = match config.upstream_auth.as_ref() {
        Some(cfg) => {
            let header_name = reqwest::header::HeaderName::from_bytes(cfg.header_name.as_bytes())
                .map_err(|_| CliError::user("invalid upstream auth header name"))?;
            let header_value = reqwest::header::HeaderValue::from_str(&cfg.header_value)
                .map_err(|_| CliError::user("invalid upstream auth header value"))?;
            Some((header_name, header_value))
        }
        None => None,
    };

    let provider = provider_name_from_upstream(&config.upstream);
    let scope_key = provider_scope_key(
        &config.upstream,
        upstream_auth.as_ref().map(|(_, value)| value.as_bytes()),
    );
    let rate_limiter = Arc::new(crate::gateway::rate_limit::AdaptiveConcurrencyLimiter::new(
        provider,
        scope_key,
        config.max_concurrency,
    ));
    let provider_cache = Arc::new(crate::gateway::cache::ProviderResponseCache::from_env().await?);
    let provider_metrics = Arc::new(crate::gateway::provider_metrics::ProviderMetrics::new(
        300, 5,
    ));

    // Phase 18: build token-consumption rate limiter from loaded config.
    let token_rate_limiter = config
        .loaded_config
        .token_rate_limit
        .clone()
        .map(|cfg| Arc::new(crate::gateway::token_rate_limit::TokenRateLimiter::new(cfg)));

    // Phase 25: validate distributed rate limit config and build DistributedState.
    // If distributed is configured but the feature is not compiled in, fail startup
    // with a clear message instead of silently degrading to local-only mode.
    #[cfg(not(feature = "distributed"))]
    if config.loaded_config.distributed_rate_limit.is_some() {
        return Err(CliError::user(
            "distributed rate limiting is configured but the CLI was built without \
             --features distributed; rebuild with 'distributed' feature enabled or \
             remove the distributed backend section from your policy config",
        ));
    }

    let DistributedReadinessBootstrap {
        distributed_state,
        rollout_grade_required,
        rollout_grade,
        rollout_grade_reasons,
        distributed_requirement: _,
    } = initialize_distributed_state_and_rollout(&config, &provider_cache).await?;

    // Phase 19: build global and IP rate limiters from loaded config.
    let global_rate_limiter = config
        .loaded_config
        .global_rate_limit
        .clone()
        .map(|cfg| Arc::new(crate::gateway::rate_limit::GlobalRateLimiter::new(cfg)));

    let ip_rate_limiter = config
        .loaded_config
        .ip_rate_limit
        .clone()
        .map(crate::gateway::rate_limit::IpRateLimiter::new)
        .transpose()
        .map_err(CliError::user)?
        .map(Arc::new);

    let user_rate_limiter = config
        .loaded_config
        .user_rate_limit
        .clone()
        .map(|cfg| Arc::new(crate::gateway::rate_limit::UserRateLimiter::new(cfg)));

    // Phase 20: build size limit middleware from loaded config.
    let size_limit = config
        .loaded_config
        .size_limits
        .clone()
        .map(|cfg| Arc::new(crate::gateway::size_limit::SizeLimitMiddleware::new(cfg)));

    let ip_allowlist = config
        .loaded_config
        .ip_allowlist
        .as_ref()
        .map(crate::gateway::network::parse_ip_allowlist)
        .transpose()
        .map_err(CliError::user)?
        .map(Arc::new);
    let ip_allowlist_trusted_proxies = config
        .loaded_config
        .ip_allowlist
        .as_ref()
        .map(|cfg| crate::gateway::network::parse_trusted_proxy_cidrs(&cfg.trusted_proxy_cidrs))
        .transpose()
        .map_err(CliError::user)?
        .unwrap_or_default();
    let cors_layer = config
        .loaded_config
        .cors
        .as_ref()
        .and_then(crate::gateway::network::build_cors_layer);

    let silent_engine = config
        .loaded_config
        .resolved_silent_engine_config()
        .map(|value| value.effective());
    let callback_root = serde_yaml::from_str::<serde_yaml::Value>(&config.loaded_config.raw_yaml)
        .ok()
        .and_then(|value| serde_json::to_value(value).ok())
        .unwrap_or_default();
    // Build callback router from declarative config.
    let callback_router = if silent_engine
        .as_ref()
        .is_some_and(|config| config.callbacks_disabled())
    {
        crate::gateway::callbacks::CallbackRouter::new(Vec::new())
    } else {
        crate::gateway::callbacks::CallbackRouter::from_json(&callback_root)
    };
    // Extract Prometheus sink reference if configured.
    let prometheus_sink = callback_router.prometheus_sink();
    let callback_router = if callback_router.is_empty() {
        None
    } else {
        Some(Arc::new(callback_router))
    };
    let client = crate::gateway::http_client::shared_gateway_http_client()
        .map_err(crate::error::CliError::internal)?;
    let connected_read_model = SharedConnectedGatewayReadModel::new(
        config.region_key.clone(),
        config.publication_catalog.clone(),
        connected_publication_catalog_refreshed_at,
        connected_routing_compatibility.clone(),
        connected_routing_compatibility_refreshed_at,
    );
    if let Some(stale_secs) = optional_env("VERDICTAN_READ_MODEL_STALE_AFTER_SECS")
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
    {
        connected_read_model.set_stale_after_secs(stale_secs);
    }
    if config.connected_mode
        && (connected_startup_relay_hmac_secret.is_some()
            || !connected_startup_peer_gateways.is_empty())
    {
        connected_read_model.record_success(
            connected_startup_region_key.clone(),
            config.publication_catalog.clone(),
            connected_routing_compatibility.clone(),
            connected_startup_peer_gateways.clone(),
            connected_startup_relay_hmac_secret.clone(),
            connected_publication_catalog_refreshed_at.unwrap_or_else(Utc::now),
        );
    }
    let gateway_id: Option<Arc<str>> = config
        .gateway_id
        .or_else(|| optional_env("VERDICTAN_GATEWAY_ID"))
        .or_else(|| {
            if config.connected_mode || event_sink.is_some() {
                let id = auto_generate_gateway_id();
                tracing::info!(
                    gateway_id = %id,
                    "auto-generated gateway ID fallback because no explicit gateway identity was provided"
                );
                Some(id)
            } else {
                None
            }
        })
        .map(Arc::from);
    let runtime_registration_id = config
        .runtime_registration_id
        .or_else(|| optional_env("VERDICTAN_RUNTIME_REGISTRATION_ID"));
    let multi_gateway_enabled = config
        .loaded_config
        .context_fabric
        .as_ref()
        .and_then(|cfg| cfg.multi_gateway.as_ref())
        .and_then(|cfg| cfg.enabled)
        .unwrap_or(false);
    let crdt_replica_id = if multi_gateway_enabled {
        let runtime_registration_id = runtime_registration_id.as_deref().ok_or_else(|| {
            CliError::user(
                "context_fabric.multi_gateway requires an authenticated runtime_registration_id UUID"
                    .to_string(),
            )
        })?;
        let parsed = uuid::Uuid::parse_str(runtime_registration_id).map_err(|_| {
            CliError::user(
                "context_fabric.multi_gateway requires runtime_registration_id to be a UUID"
                    .to_string(),
            )
        })?;
        Arc::<str>::from(parsed.hyphenated().to_string())
    } else {
        gateway_id
            .clone()
            .unwrap_or_else(|| Arc::from(auto_generate_gateway_id()))
    };
    let crdt_auth_client = build_crdt_auth_client(
        api_base_url.as_deref(),
        config.event_sink.as_ref(),
        runtime_registration_id.as_deref(),
        multi_gateway_enabled,
    )
    .await?;
    let crdt_auth_shutdown = crdt_auth_client.as_ref().map(|client| {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        client.spawn_refresh_loop_with_shutdown(shutdown_rx);
        Arc::new(shutdown_tx)
    });
    let crdt_sync_runtime = SharedCrdtSyncRuntime::default();
    crdt_sync_runtime.replace(
        crdt_replica_id.as_ref(),
        config.loaded_config.context_fabric.as_ref(),
        crdt_auth_client.clone(),
        Some(connected_read_model.clone()),
    )?;
    let mcp_outbox = Arc::new(
        config
            .mcp_outbox
            .take()
            .unwrap_or_else(crate::mcp::audit::McpOutboxHandle::from_env),
    );
    let pending_mcp_effects = crate::mcp::audit::read_outbox_records(mcp_outbox.as_ref())?
        .into_iter()
        .filter(|record| matches!(record.state.as_str(), "dispatched" | "indeterminate"))
        .count();
    if pending_mcp_effects > 0 {
        let recovery_api_url = api_base_url.as_deref().ok_or_else(|| {
            CliError::internal(format!(
                "{pending_mcp_effects} sealed MCP effects require recovery, but the control-plane URL is unavailable"
            ))
        })?;
        let recovery_token = optional_env("VERDICTAN_API_TOKEN").ok_or_else(|| {
            CliError::internal(format!(
                "{pending_mcp_effects} sealed MCP effects require recovery, but VERDICTAN_API_TOKEN is unavailable"
            ))
        })?;
        let recovery_client = crate::api::AsyncApiClient::new(recovery_api_url, recovery_token)?
            .with_region(config.region_key.clone());
        let recovery =
            crate::mcp::audit::recover_sealed_outbox(mcp_outbox.as_ref(), &recovery_client).await?;
        if !recovery.unresolved.is_empty() {
            let execution_ids = recovery
                .unresolved
                .iter()
                .map(|effect| effect.execution_idempotency_key.to_string())
                .collect::<Vec<_>>()
                .join(",");
            return Err(CliError::internal(format!(
                "{} sealed MCP effects remain unresolved after startup recovery; execution ids: {execution_ids}",
                recovery.unresolved.len()
            )));
        }
        tracing::info!(
            recovered_effects = recovery.completed,
            "completed sealed MCP outbox recovery before serving requests"
        );
    }
    let mcp_sessions = crate::mcp::transport::streamable_http::StreamableHttpState::default();
    mcp_sessions.spawn_background_session_cleanup();

    let state = GatewayState {
        gateway_id,
        crdt_replica_id,
        crdt_auth_client,
        crdt_auth_shutdown,
        runtime_registration_id,
        connected_read_model,
        catalog_resolver: catalog_resolver.clone(),
        source_config_path: config.source_config_path.clone(),
        upstream_base: config.upstream,
        upstream_auth,
        fail_mode: config.fail_mode,
        client: client.clone(),
        api_base_url,
        admin_bearer_token: resolve_admin_bearer_token(
            config.admin_local_only,
            control_plane_available,
        ),
        event_sink,
        mcp_sessions,
        crdt_sync_runtime,
        agent_context_service,
        history_service,
        admin_local_only: config.admin_local_only,
        active_config: SharedGatewayConfig::new(config.loaded_config.clone()),
        rate_limiter,
        provider_cache,
        provider_metrics,
        global_rate_limiter,
        ip_rate_limiter,
        user_rate_limiter,
        token_rate_limiter,
        size_limit,
        ip_allowlist,
        ip_allowlist_trusted_proxies: Arc::new(ip_allowlist_trusted_proxies),
        connected_mode: config.connected_mode,
        prometheus_sink,
        callback_router,
        distributed_state,
        mcp_outbox: mcp_outbox.clone(),
        token_validation_cache: Arc::new(
            crate::gateway::token_validation_cache::TokenValidationCache::new(
                4096,
                Duration::from_secs(5),
            ),
        ),
        gateway_runtime_metrics: Arc::new(GatewayRuntimeMetrics::default()),
        rollout_grade,
        rollout_grade_required,
        rollout_grade_reasons: Arc::new(rollout_grade_reasons.clone()),
        key_rate_limiter: Arc::new(crate::gateway::rate_limit::TokenRateLimiter::new()),
        key_request_tracker: Arc::new(
            crate::gateway::token_rate_limit::TokenRequestTracker::default(),
        ),
        key_budget_tracker: Arc::new(
            crate::gateway::token_rate_limit::TokenBudgetTracker::default(),
        ),
        reload_guard: Arc::new(tokio::sync::Mutex::new(())),
        in_flight_tasks: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        admission_controller: crate::gateway::admission_control::AdmissionController::new(
            None, None, None,
        ),
        health_monitor: Arc::new(crate::gateway::health_monitor::ProviderHealthMonitor::new()),
        ai_usage_capture_config: config
            .loaded_config
            .ai_usage_streaming
            .as_ref()
            .map(|c| c.to_capture_config())
            .unwrap_or_default(),
    };

    // Start health monitor probe tasks if configured.
    if let Some(ref hm_cfg) = config.loaded_config.health_monitor {
        if !hm_cfg.providers.is_empty() {
            let credentials: Vec<crate::gateway::health_monitor::MonitoredCredential> = hm_cfg
                .providers
                .iter()
                .map(|p| crate::gateway::health_monitor::MonitoredCredential {
                    id: p.name.clone(),
                    provider_id: p.name.clone(),
                    endpoint_url: p.endpoint.clone(),
                })
                .collect();
            tracing::info!(
                provider_count = credentials.len(),
                "starting health monitor probe tasks"
            );
            state.health_monitor.spawn_probe_tasks(credentials);
        }
    }

    // Force-register all Prometheus metrics with the global registry so
    // /metrics returns metric families even before the first request.
    crate::gateway::metrics::init();

    let app = Router::new()
        .route("/healthz", get(proxy_health))
        .route("/livez", get(proxy_liveness))
        .route("/readyz", get(proxy_readiness))
        .route("/verdictan/config", get(proxy_config))
        .route("/verdictan/config/reload", post(reload_proxy_config))
        .route(
            "/verdictan/cache/invalidate",
            post(invalidate_gateway_cache),
        )
        .route(
            "/verdictan/providers/metrics",
            get(provider_metrics_endpoint),
        )
        .route("/metrics", get(prometheus_metrics_handler))
        .route(
            "/verdictan/compliance/report",
            axum::routing::post(compliance_report_handler),
        )
        .route("/internal/crdt/sync", post(crdt_sync_post))
        .route(
            "/verdictan/relay",
            post(crate::gateway::relay::handle_relay_request),
        )
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/responses", post(responses))
        .route("/v1/messages", post(self::messages))
        .route("/v1/chat/completions/ws", get(chat_completions_ws))
        .route("/v1/responses/ws", get(responses_ws))
        .route("/mcp", get(mcp_get).post(mcp_post))
        .route("/v1/models", get(list_models))
        .route("/v1/models/:model_id", get(get_model))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/audio/transcriptions", post(audio_transcriptions))
        .route("/v1/audio/speech", post(audio_speech))
        .route("/v1/completions", post(completions))
        .route("/v1/moderations", post(moderations))
        .with_state(state.clone());
    let app = if let Some(cors_layer) = cors_layer {
        app.layer(cors_layer)
    } else {
        app
    };

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|e| CliError::network(format!("failed to bind gateway listener: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| CliError::internal(format!("failed to get local addr: {e}")))?;

    spawn_provider_health_probe_loop(state.clone());

    // Gateway telemetry — push periodic snapshots to the API when configured.
    if !silent_engine
        .as_ref()
        .is_some_and(|config| config.gateway_telemetry_disabled())
    {
        if let (Some(ref sink), Some(ref runtime_registration_id)) =
            (&state.event_sink, &state.runtime_registration_id)
        {
            let advertise_addr = optional_env("VERDICTAN_ADVERTISE_ADDRESS")
                .or_else(|| Some(format!("http://{addr}")));
            let reporter_config = crate::gateway::telemetry_reporter::TelemetryReporterConfig {
                api_base_url: sink.base_url.clone(),
                runtime_registration_id: runtime_registration_id.clone(),
                gateway_id: state.gateway_id.clone(),
                connected_read_model: state.connected_read_model.clone(),
                interval: std::time::Duration::from_secs(30),
                client: sink.client.clone(),
                gateway_service_token: optional_env("VERDICTAN_API_TOKEN"),
                rollout_grade: state.rollout_grade,
                rollout_grade_reasons: (*state.rollout_grade_reasons).clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                config_sha256: state.active_config.snapshot().config_sha256,
                listen_address: advertise_addr.clone(),
                relay_endpoint: optional_env("VERDICTAN_RELAY_ENDPOINT").or(advertise_addr),
                service_manager: optional_env("VERDICTAN_RUNTIME_SERVICE_MANAGER")
                    .unwrap_or_else(|| "manual".to_string()),
                upgrade_status: optional_env("VERDICTAN_RUNTIME_UPGRADE_PHASE")
                    .unwrap_or_else(|| "succeeded".to_string()),
                last_restart_at: optional_env("VERDICTAN_RUNTIME_LAST_RESTART_AT"),
                active_binary_path: optional_env("VERDICTAN_RUNTIME_ACTIVE_BINARY_PATH"),
                target_version: optional_env("VERDICTAN_RUNTIME_TARGET_VERSION"),
                target_binary_path: optional_env("VERDICTAN_RUNTIME_TARGET_BINARY_PATH"),
                image_digest: optional_env("VERDICTAN_RUNTIME_IMAGE_DIGEST"),
                build_digest: optional_env("VERDICTAN_RUNTIME_BUILD_DIGEST"),
            };
            crate::gateway::telemetry_reporter::spawn_telemetry_reporter(
                reporter_config,
                state.provider_metrics.clone(),
                std::time::Instant::now(),
                state.active_config.clone(),
            );
        }
    }

    if state.connected_mode {
        if let (Some(ref sink), Some(ref runtime_registration_id)) =
            (&state.event_sink, &state.runtime_registration_id)
        {
            spawn_connected_read_model_refresh_loop(
                sink.clone(),
                runtime_registration_id.clone(),
                local_hosted_gateway.clone(),
                state.active_config.clone(),
                state.connected_read_model.clone(),
                state.catalog_resolver.clone(),
                state.reload_guard.clone(),
                state.gateway_id.as_deref().map(ToString::to_string),
            );
        }
    }

    // Reverse-tunnel relay client — connects to the platform's WebSocket relay
    // endpoint so external gateways behind NAT/firewalls can receive inbound
    // API traffic through the tunnel.
    if state.connected_mode {
        if let (Some(ref api_base_url), Some(ref runtime_registration_id)) =
            (&state.api_base_url, &state.runtime_registration_id)
        {
            if let Some(api_token) = optional_env("VERDICTAN_API_TOKEN") {
                crate::gateway::relay_client::spawn_relay_client(
                    crate::gateway::relay_client::RelayClientConfig {
                        api_base_url: api_base_url.clone(),
                        api_token,
                        runtime_registration_id: runtime_registration_id.clone(),
                        local_gateway_port: addr.port(),
                    },
                );
            }
        }
    }

    {
        let cache = Arc::clone(&state.token_validation_cache);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                cache.reap_expired();
            }
        });
    }

    // Gateway execution session poll loop (RUNNER-010 / RUNNER-011).
    //
    // Only active when both `VERDICTAN_API_URL` and `VERDICTAN_GATEWAY_ID`
    // are set, which identifies this instance as a registered gateway.
    if !state.connected_mode {
        if let Some(execution_cfg) = crate::gateway::runner::RunnerSessionExecutorConfig::from_env()
        {
            if let Some(ref gateway_id) = execution_cfg.gateway_id.clone() {
                match crate::gateway::runner::RunnerSessionExecutor::new(execution_cfg) {
                    Ok(executor) => {
                        crate::gateway::runner::spawn_runner_poll_loop(
                            crate::gateway::runner::RunnerPollConfig {
                                executor,
                                gateway_id: gateway_id.clone(),
                                poll_interval: Duration::from_secs(10),
                            },
                        );
                        tracing::info!(
                            gateway_id = %gateway_id,
                            "gateway execution session poll loop started"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "failed to build gateway execution session executor; gateway execution poll loop disabled"
                        );
                    }
                }
            }
        }
    }

    let shutdown_join_set = state
        .event_sink
        .as_ref()
        .map(|sink| Arc::clone(&sink.forward_join_set));

    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = rx.await;
            drain_forwarding_tasks_on_shutdown(shutdown_join_set).await;
        })
        .await;
    });

    Ok(GatewayHandle { addr, shutdown: tx })
}

#[cfg(test)]
mod admin_secret_file_tests {
    use super::*;
    use std::ffi::OsString;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    struct EnvGuard {
        home: Option<OsString>,
        xdg_runtime_dir: Option<OsString>,
    }

    impl EnvGuard {
        fn capture() -> Self {
            Self {
                home: std::env::var_os("HOME"),
                xdg_runtime_dir: std::env::var_os("XDG_RUNTIME_DIR"),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.home {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match &self.xdg_runtime_dir {
                Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }
    }

    #[test]
    fn write_admin_secret_file_writes_owner_only_secret_under_home() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        std::env::remove_var("XDG_RUNTIME_DIR");
        std::env::set_var("HOME", temp.path());

        let path = write_admin_secret_file("test-admin-secret").expect("write admin secret");
        assert_eq!(path, temp.path().join(".verdictan").join("admin.secret"));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read secret"),
            "test-admin-secret"
        );

        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn write_admin_secret_file_returns_none_when_directory_creation_fails() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let _guard = EnvGuard::capture();
        let temp = tempdir().expect("tempdir");
        let blocked_home = temp.path().join("blocked-home");
        std::fs::write(&blocked_home, "occupied").expect("write blocked home file");
        std::env::remove_var("XDG_RUNTIME_DIR");
        std::env::set_var("HOME", &blocked_home);

        assert!(write_admin_secret_file("test-admin-secret").is_none());
    }
}
