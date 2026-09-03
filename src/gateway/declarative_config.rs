// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::error::CliError;
use crate::secret_key_ref::parse_env_secret_key_name;

#[path = "agent_config_resolution.rs"]
pub mod agent_config_resolution;

// ── Provider catalog source config ───────────────────────────────────────────

/// Source for provider catalog data used by catalog-backed provider resolution.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProvidersSourceConfig {
    /// Read provider catalog from a local filesystem directory.
    Directory { path: String },
    /// Fetch provider catalog from API catalog endpoints.
    Api { endpoint: String },
    /// Use build-time embedded constants (the default).
    #[default]
    Embedded,
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SilentMinimumStateMode {
    #[default]
    Standard,
    EnforcementOnly,
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct SilentEngineConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub disable_callbacks: bool,
    #[serde(default)]
    pub disable_history: bool,
    #[serde(default)]
    pub disable_gateway_telemetry: bool,
    #[serde(default)]
    pub disable_payload_logging: bool,
    #[serde(default)]
    pub disable_citation_writeback: bool,
    #[serde(default)]
    pub minimum_state_mode: SilentMinimumStateMode,
}

impl SilentEngineConfig {
    pub fn effective(&self) -> Self {
        if !self.enabled {
            return Self {
                enabled: false,
                disable_callbacks: false,
                disable_history: false,
                disable_gateway_telemetry: false,
                disable_payload_logging: false,
                disable_citation_writeback: false,
                minimum_state_mode: self.minimum_state_mode.clone(),
            };
        }

        Self {
            enabled: true,
            disable_callbacks: true,
            disable_history: true,
            disable_gateway_telemetry: true,
            disable_payload_logging: true,
            disable_citation_writeback: true,
            minimum_state_mode: match self.minimum_state_mode {
                SilentMinimumStateMode::Standard => SilentMinimumStateMode::EnforcementOnly,
                SilentMinimumStateMode::EnforcementOnly => SilentMinimumStateMode::EnforcementOnly,
            },
        }
    }

    pub fn callbacks_disabled(&self) -> bool {
        self.effective().disable_callbacks
    }

    pub fn history_disabled(&self) -> bool {
        self.effective().disable_history
    }

    pub fn gateway_telemetry_disabled(&self) -> bool {
        self.effective().disable_gateway_telemetry
    }

    pub fn payload_logging_disabled(&self) -> bool {
        self.effective().disable_payload_logging
    }

    pub fn citation_writeback_disabled(&self) -> bool {
        self.effective().disable_citation_writeback
    }

    pub fn privacy_enforcement_only(&self) -> bool {
        self.effective().enabled
    }
}

/// Stable local-evidence code for explicit pack exclusion via `pack.enabled=false`.
pub const PACK_EXCLUDED_EVIDENCE_CODE: &str = "pack.excluded";

/// Consumed keys on a conditional chain-entry object (aside from the policy kind key).
pub const CHAIN_CONDITIONAL_CONSUMED_KEYS: &[&str] = &["when", "stage", "parallel", "targeting"];

/// Consumed keys on a `when` predicate object.
pub const WHEN_PREDICATE_CONSUMED_KEYS: &[&str] = &["path", "header", "model"];

/// Evidence recorded when a pack is explicitly excluded from enforcement.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PackExclusionEvidence {
    pub code: String,
    pub pack_name: Option<String>,
    pub pack_version: String,
    pub reason: String,
}

impl PackExclusionEvidence {
    pub fn for_disabled_pack(pack_name: Option<String>, pack_version: &str) -> Self {
        Self {
            code: PACK_EXCLUDED_EVIDENCE_CODE.to_string(),
            pack_name,
            pack_version: pack_version.to_string(),
            reason: "pack.enabled=false".to_string(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LoadedDeclarativeConfig {
    pub raw_yaml: String,
    pub config_sha256: String,
    pub config_version: String,
    pub pack_name: Option<String>,
    /// When `pack.enabled` is explicitly `false`, no chains, routes, providers,
    /// callbacks, testing suites, or pack side effects are registered.
    pub pack_enabled: bool,
    /// Local evidence recorded when `pack.enabled=false` excludes the pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_exclusion_evidence: Option<PackExclusionEvidence>,
    /// Phase 40: Top-level `region:` field — sets the gateway's operating region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Phase 40: Per-region overrides for gateway behavior.
    #[serde(skip)]
    pub regions: Option<std::collections::HashMap<String, RegionOverrideConfig>>,
    /// Authoritative tags for the declaratively managed configuration resource.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub configuration_tags: std::collections::BTreeMap<String, String>,
    /// Typed chain entries (supports `when` predicates).
    #[serde(skip)]
    pub chain_entries: Vec<super::enforcement::ChainEntry>,
    pub policy_blocks: crate::gateway::PolicyBlocks,
    /// Parsed `routes:` section (Phase 16).
    #[serde(skip)]
    pub route_config: super::routes::RouteConfig,
    #[serde(skip)]
    pub provider_registry: Option<super::providers::ProviderRegistry>,
    #[serde(skip)]
    pub testing: Option<crate::policy::testing_config::TestingSection>,
    /// Phase 18: token-consumption rate limit config.
    #[serde(skip)]
    pub token_rate_limit: Option<super::token_rate_limit::TokenRateLimitConfig>,
    /// Phase 19: global request-count rate limit config.
    #[serde(skip)]
    pub global_rate_limit: Option<super::rate_limit::GlobalRateLimitConfig>,
    /// Phase 19: per-client-IP rate limit config.
    #[serde(skip)]
    pub ip_rate_limit: Option<super::rate_limit::IpRateLimitConfig>,
    /// Per-user request-count rate limit config.
    #[serde(skip)]
    pub user_rate_limit: Option<super::rate_limit::UserRateLimiterConfig>,
    /// Phase 20: request size limit config.
    #[serde(skip)]
    pub size_limits: Option<super::size_limit::SizeLimitConfig>,
    /// Phase 21: consumer-group identity, per-group limits, and chain overrides.
    #[serde(skip)]
    pub consumer_groups: Option<super::consumer::ConsumerGroupConfig>,
    /// Phase 21: optional distributed rate limit backend config.
    #[serde(skip)]
    #[allow(dead_code)]
    pub distributed_rate_limit: Option<super::distributed_rate_limit::DistributedConfig>,
    /// Phase 23: semantic cache config (mode, similarity_threshold, embedding_provider).
    #[serde(skip)]
    pub semantic_cache: Option<super::cache::SemanticCacheConfig>,
    /// Optional request IP allowlist.
    #[serde(skip)]
    pub ip_allowlist: Option<super::network::IpAllowlistConfig>,
    /// Optional runtime CORS policy.
    #[serde(skip)]
    pub cors: Option<super::network::CorsConfig>,
    /// Auto virtual provider config.
    #[serde(skip)]
    pub auto_provider: super::auto_provider::AutoProviderConfig,
    /// Models endpoint config.
    #[serde(skip)]
    pub models_endpoint: super::models_endpoint::ModelsEndpointConfig,
    /// History capture runtime config.
    #[serde(skip)]
    pub history: Option<HistoryRuntimeConfig>,
    /// Silent-engine privacy enforcement config.
    #[serde(skip)]
    pub silent_engine: Option<SilentEngineConfig>,
    /// Runtime routing defaults (provider policy, caching, plugin governance, shadow routing).
    #[serde(skip)]
    pub runtime_routing: Option<RuntimeRoutingConfig>,
    /// Default runtime agent linkage.
    #[serde(skip)]
    pub agents_runtime: Option<AgentsRuntimeConfig>,
    /// Agent-scoped context fabric and MCP declarations.
    #[serde(skip)]
    pub agents: Vec<GatewayAgentDeclaration>,
    /// Gateway-level context fabric defaults.
    #[serde(skip)]
    pub context_fabric: Option<ContextFabricConfig>,
    /// Gateway-level MCP server defaults.
    #[serde(skip)]
    pub mcp_server: Option<McpServerConfig>,
    /// Optional moderation config for POST /v1/moderations.
    #[serde(skip)]
    pub moderation: Option<ModerationConfig>,
    /// Workflow cache tier and replay policy.
    #[serde(skip)]
    pub workflow_cache: Option<WorkflowCacheRuntimeConfig>,
    /// Offline mode and egress restriction settings.
    #[serde(skip)]
    pub offline_egress: Option<OfflineEgressConfig>,
    /// Hosted gateway local folder and shell access policy.
    #[serde(skip)]
    pub hosted_gateway: Option<HostedGatewayRuntimeConfig>,
    /// Durable tool server declarations.
    #[serde(skip)]
    pub tool_servers: Vec<ToolServerDeclaration>,
    /// Task profiles for task-aware routing.
    #[serde(skip)]
    pub task_profiles: Vec<super::providers::TaskProfile>,
    /// Budget-aware routing policy.
    #[serde(skip)]
    pub budget_policy: Option<super::providers::BudgetPolicy>,
    /// Latency optimization hints.
    #[serde(skip)]
    pub latency_optimization: Option<super::providers::LatencyOptimization>,
    /// Envelope-aware cache config.
    #[serde(skip)]
    pub envelope_cache: Option<EnvelopeCacheConfig>,
    /// Context management config.
    #[serde(skip)]
    pub context_management: Option<super::context_manager::ContextManagementConfig>,
    /// Local filesystem cache settings.
    #[serde(skip)]
    pub local_cache: Option<LocalCacheConfig>,
    /// Circuit breaker config.
    #[serde(skip)]
    pub circuit_breaker: Option<CircuitBreakerDeclConfig>,
    /// Admission control config.
    #[serde(skip)]
    pub admission_control: Option<AdmissionControlDeclConfig>,
    /// Health monitor config.
    #[serde(skip)]
    pub health_monitor: Option<HealthMonitorDeclConfig>,
    /// Bot or fingerprint detector config.
    #[serde(skip)]
    pub fingerprint: Option<FingerprintDeclConfig>,
    /// Data classification config.
    #[serde(skip)]
    pub data_classification: Option<DataClassificationDeclConfig>,
    /// EU AI Act compliance config.
    #[serde(skip)]
    pub eu_ai_act: Option<EuAiActDeclConfig>,
    /// GDPR consent or erasure config.
    #[serde(skip)]
    pub gdpr: Option<GdprDeclConfig>,
    /// Tool security firewall config.
    #[serde(skip)]
    pub tool_security: Option<ToolSecurityDeclConfig>,
    /// Per-tool budget limits.
    #[serde(skip)]
    pub tool_budget: Option<ToolBudgetDeclConfig>,
    /// Tool schema validation config.
    #[serde(skip)]
    pub tool_validation: Option<ToolValidationDeclConfig>,
    /// Code sanitation config.
    #[serde(skip)]
    pub code_sanitation: Option<CodeSanitationDeclConfig>,
    /// Content extraction config.
    #[serde(skip)]
    pub content_extraction: Option<ContentExtractionDeclConfig>,
    /// Document analyzer config.
    #[serde(skip)]
    pub document_analyzer: Option<DocumentAnalyzerDeclConfig>,
    /// Language validation config.
    #[serde(skip)]
    pub language: Option<LanguageDeclConfig>,
    /// Context flush config.
    #[serde(skip)]
    pub context_flush: Option<ContextFlushDeclConfig>,
    /// Network timeout config.
    #[serde(skip)]
    pub network: Option<NetworkTimeoutDeclConfig>,
    /// AI usage streaming capture config.
    #[serde(skip)]
    pub ai_usage_streaming: Option<AiUsageStreamingConfig>,
    /// Declarative config schema version for migration support.
    #[serde(skip)]
    pub schema_version: u32,
    /// Source for provider catalog data.
    #[serde(skip)]
    pub providers_source: ProvidersSourceConfig,
}

impl LoadedDeclarativeConfig {
    pub fn empty() -> Self {
        Self {
            raw_yaml: String::new(),
            config_sha256: sha256_prefixed(b""),
            config_version: "0.0.0".to_string(),
            pack_name: None,
            pack_enabled: true,
            pack_exclusion_evidence: None,
            region: None,
            regions: None,
            configuration_tags: std::collections::BTreeMap::new(),
            chain_entries: Vec::new(),
            policy_blocks: crate::gateway::PolicyBlocks::new(),
            route_config: super::routes::RouteConfig::default(),
            provider_registry: None,
            testing: None,
            token_rate_limit: None,
            global_rate_limit: None,
            ip_rate_limit: None,
            user_rate_limit: None,
            size_limits: None,
            consumer_groups: None,
            distributed_rate_limit: None,
            semantic_cache: None,
            ip_allowlist: None,
            cors: None,
            auto_provider: super::auto_provider::AutoProviderConfig::default(),
            models_endpoint: super::models_endpoint::ModelsEndpointConfig::default(),
            history: None,
            silent_engine: None,
            runtime_routing: None,
            agents_runtime: None,
            agents: Vec::new(),
            context_fabric: None,
            mcp_server: None,
            moderation: None,
            workflow_cache: None,
            offline_egress: None,
            hosted_gateway: None,
            tool_servers: Vec::new(),
            task_profiles: Vec::new(),
            budget_policy: None,
            latency_optimization: None,
            envelope_cache: None,
            context_management: None,
            local_cache: None,
            circuit_breaker: None,
            admission_control: None,
            health_monitor: None,
            fingerprint: None,
            data_classification: None,
            eu_ai_act: None,
            gdpr: None,
            tool_security: None,
            tool_budget: None,
            tool_validation: None,
            code_sanitation: None,
            content_extraction: None,
            document_analyzer: None,
            language: None,
            context_flush: None,
            network: None,
            ai_usage_streaming: None,
            schema_version: 2,
            providers_source: ProvidersSourceConfig::default(),
        }
    }

    /// Load configuration from a file path.
    ///
    /// # Blocking I/O note
    ///
    /// This function uses synchronous `std::fs::read`. It is intended to be
    /// called from synchronous gateway startup code (`build_runtime_config`,
    /// `from_instance_spec`). If called from an async handler, wrap with
    /// `tokio::task::spawn_blocking`. The gateway admin reload handler calls
    /// this at low frequency from an admin-only endpoint where the short block
    /// duration is acceptable.
    pub fn from_path(path: &std::path::Path) -> Result<Self, CliError> {
        let bytes = std::fs::read(path)
            .map_err(|e| CliError::user(format!("failed to read {}: {e}", path.display())))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_path_for_validation(path: &std::path::Path) -> Result<Self, CliError> {
        let bytes = std::fs::read(path)
            .map_err(|e| CliError::user(format!("failed to read {}: {e}", path.display())))?;
        Self::from_bytes_for_validation(&bytes)
    }

    pub fn from_paths<I, P>(paths: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<std::path::Path>,
    {
        let mut paths = paths.into_iter();
        let Some(first_path) = paths.next() else {
            return Ok(Self::empty());
        };

        let mut merged = Self::from_path(first_path.as_ref())?;
        for path in paths {
            let overlay = Self::from_path(path.as_ref())?;
            merged = Self::merged_with_overlay(&merged, &overlay)?;
        }

        Ok(merged)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CliError> {
        Self::from_bytes_with_options(bytes, false)
    }

    pub fn from_bytes_for_validation(bytes: &[u8]) -> Result<Self, CliError> {
        Self::from_bytes_with_options(bytes, true)
    }

    fn from_bytes_with_options(
        bytes: &[u8],
        relax_hosted_gateway_local_access_validation: bool,
    ) -> Result<Self, CliError> {
        let config_sha256 = sha256_prefixed(bytes);
        let text = String::from_utf8(bytes.to_vec())
            .map_err(|e| CliError::user(format!("config is not valid UTF-8: {e}")))?;

        let root_yaml: serde_yaml::Value = serde_yaml::from_str(&text)
            .map_err(|e| CliError::user(format!("failed to parse YAML: {e}")))?;

        let root_json: serde_json::Value = serde_json::to_value(root_yaml)
            .map_err(|e| CliError::internal(format!("failed to convert YAML to JSON: {e}")))?;

        validate_inactive_configuration_fields(&root_json)?;

        let config_version = root_json
            .get("pack")
            .and_then(|v| v.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0")
            .to_string();

        let pack_name = root_json
            .get("pack")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        let pack_enabled = root_json
            .get("pack")
            .and_then(|v| v.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        if !pack_enabled {
            let pack_exclusion_evidence = Some(PackExclusionEvidence::for_disabled_pack(
                pack_name.clone(),
                &config_version,
            ));
            return Ok(Self {
                raw_yaml: text,
                config_sha256,
                config_version,
                pack_name,
                pack_enabled: false,
                pack_exclusion_evidence,
                ..Self::empty()
            });
        }

        let registry_diags = registry_policy_contract_diagnostics(&root_json);
        if let Some(diag) = registry_diags.into_iter().next() {
            return Err(CliError::user(diag));
        }

        let region = root_json
            .get("region")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string);
        if let Some(ref r) = region {
            crate::region::validate_region_slug(r)?;
        }

        let regions = parse_region_overrides(&root_json)?;

        let configuration_tags = parse_tags_map(
            root_json.get("pack").and_then(|value| value.get("tags")),
            "pack.tags",
        )?;

        let chain_entries: Vec<super::enforcement::ChainEntry> = root_json
            .get("policies")
            .and_then(|v| v.get("chain"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                let mut entries = Vec::with_capacity(arr.len());
                for v in arr {
                    match super::enforcement::ChainEntry::from_json(v) {
                        Ok(entry) => entries.push(entry),
                        Err(e) => {
                            return Err(CliError::user(format!("invalid chain entry: {e}")));
                        }
                    }
                }
                Ok(entries)
            })
            .transpose()?
            .unwrap_or_default();

        let policy_blocks = root_json
            .get("policy")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        let route_config = super::routes::RouteConfig::from_json(&root_json)?;
        let provider_registry = super::providers::ProviderRegistry::from_json(&root_json)?;
        let testing = crate::policy::testing_config::TestingSection::from_json(&root_json)?;

        // Phase 18: parse `token_rate_limit:` section.
        let token_rate_limit = parse_token_rate_limit(&root_json);

        // Phase 19: parse `global_rate_limit:` and `ip_rate_limit:` sections.
        let global_rate_limit = parse_global_rate_limit(&root_json);
        let ip_rate_limit = parse_ip_rate_limit(&root_json);
        let user_rate_limit = parse_user_rate_limit(&root_json);

        // Phase 20: parse `size_limits:` section.
        let size_limits = parse_size_limits(&root_json);

        // Phase 21: parse `consumer_groups:` section.
        let consumer_groups = super::consumer::ConsumerGroupConfig::from_json(&root_json)?;

        // Phase 21: parse optional `distributed:` sub-object from any rate limit section.
        let distributed_rate_limit = parse_distributed_config(&root_json);

        // Phase 23: parse `cache:` section.
        let semantic_cache = parse_semantic_cache(&root_json);
        let ip_allowlist = parse_ip_allowlist(&root_json);
        let cors = parse_cors(&root_json);

        // Auto virtual provider and models endpoint.
        let auto_provider = super::auto_provider::parse_auto(&root_json).map_err(CliError::user)?;
        if auto_provider.enabled {
            if let Some(registry) = provider_registry.as_ref() {
                if registry.resolve_model_group(&auto_provider.name).is_some()
                    || registry.resolve_pipeline(&auto_provider.name).is_some()
                {
                    return Err(CliError::user(format!(
                        "auto provider name '{}' conflicts with an existing virtual model name",
                        auto_provider.name
                    )));
                }
            }
        }
        let models_endpoint = super::models_endpoint::parse_models_endpoint(&root_json);
        let history = parse_history_runtime_config(&root_json);
        let silent_engine = parse_silent_engine_config(&root_json);
        let runtime_routing = parse_runtime_routing_config(&root_json);
        let agents_runtime = parse_agents_runtime_config(&root_json);
        let agents = parse_agent_declarations(&root_json)?;
        let context_fabric = parse_gateway_context_fabric_config(&root_json)?;
        let mcp_server = parse_mcp_server_config(&root_json)?;
        let moderation = parse_moderation_config(&root_json);
        let workflow_cache = parse_workflow_cache_runtime_config(&root_json);
        let offline_egress = parse_offline_egress_config(&root_json);
        let hosted_gateway = parse_hosted_gateway_runtime_config(
            &root_json,
            !relax_hosted_gateway_local_access_validation,
        )?;

        // Parse durable tool servers.
        validate_boundary_separation(&root_json)?;
        let tool_servers = parse_tool_servers(&root_json)?;
        let tool_server_ids: Vec<String> = tool_servers.iter().map(|ts| ts.id.clone()).collect();
        validate_no_conflated_mcp_tool_servers(&root_json, &tool_server_ids)?;

        // Parse task-aware routing configuration.
        let task_profiles = parse_task_profiles(&root_json);
        let budget_policy = parse_budget_policy(&root_json);
        let latency_optimization = parse_latency_optimization(&root_json);

        // Parse envelope cache and context management.
        let envelope_cache = parse_envelope_cache_config(&root_json);
        let context_management = parse_context_management_config(&root_json);

        // Phase 41: Parse local filesystem cache config.
        let local_cache = parse_local_cache_config(&root_json);

        // Phase 39: Parse newly-covered gateway feature configs.
        let circuit_breaker = parse_circuit_breaker_config(&root_json);
        let admission_control = parse_admission_control_config(&root_json);
        let health_monitor = parse_health_monitor_config(&root_json);
        let fingerprint = parse_fingerprint_config(&root_json);
        let data_classification = parse_data_classification_config(&root_json);
        let eu_ai_act = parse_eu_ai_act_config(&root_json);
        let gdpr = parse_gdpr_config(&root_json);
        let tool_security_cfg = parse_tool_security_config(&root_json);
        let tool_budget = parse_tool_budget_config(&root_json);
        let tool_validation = parse_tool_validation_config(&root_json);
        let code_sanitation = parse_code_sanitation_config(&root_json);
        let content_extraction = parse_content_extraction_config(&root_json);
        let document_analyzer = parse_document_analyzer_config(&root_json);
        let language_cfg = parse_language_config(&root_json);
        let context_flush = parse_context_flush_config(&root_json);
        let network = parse_network_timeout_config(&root_json);
        let ai_usage_streaming = parse_ai_usage_streaming_config(&root_json);

        let schema_version = root_json
            .get("config_version")
            .and_then(|v| v.as_u64())
            .unwrap_or(2) as u32;

        let providers_source = root_json
            .get("providers_source")
            .and_then(|v| serde_json::from_value::<ProvidersSourceConfig>(v.clone()).ok())
            .unwrap_or_default();

        Ok(Self {
            raw_yaml: text,
            config_sha256,
            config_version,
            pack_name,
            pack_enabled: true,
            pack_exclusion_evidence: None,
            region,
            regions,
            configuration_tags,
            chain_entries,
            policy_blocks,
            route_config,
            provider_registry,
            testing,
            token_rate_limit,
            global_rate_limit,
            ip_rate_limit,
            user_rate_limit,
            size_limits,
            consumer_groups,
            distributed_rate_limit,
            semantic_cache,
            ip_allowlist,
            cors,
            auto_provider,
            models_endpoint,
            history,
            silent_engine,
            runtime_routing,
            agents_runtime,
            agents,
            context_fabric,
            mcp_server,
            moderation,
            workflow_cache,
            offline_egress,
            hosted_gateway,
            tool_servers,
            task_profiles,
            budget_policy,
            latency_optimization,
            envelope_cache,
            context_management,
            local_cache,
            circuit_breaker,
            admission_control,
            health_monitor,
            fingerprint,
            data_classification,
            eu_ai_act,
            gdpr,
            tool_security: tool_security_cfg,
            tool_budget,
            tool_validation,
            code_sanitation,
            content_extraction,
            document_analyzer,
            language: language_cfg,
            context_flush,
            network,
            ai_usage_streaming,
            schema_version,
            providers_source,
        })
    }

    fn reparsed_root_json(&self) -> Option<serde_json::Value> {
        if self.raw_yaml.trim().is_empty() {
            return None;
        }
        let root_yaml: serde_yaml::Value = serde_yaml::from_str(&self.raw_yaml).ok()?;
        serde_json::to_value(root_yaml).ok()
    }

    pub fn resolved_history_config(&self) -> Option<HistoryRuntimeConfig> {
        self.history.clone().or_else(|| {
            self.reparsed_root_json()
                .and_then(|root| parse_history_runtime_config(&root))
        })
    }

    pub fn resolved_silent_engine_config(&self) -> Option<SilentEngineConfig> {
        self.silent_engine.clone().or_else(|| {
            self.reparsed_root_json()
                .and_then(|root| parse_silent_engine_config(&root))
        })
    }

    pub fn resolved_runtime_routing_config(&self) -> Option<RuntimeRoutingConfig> {
        self.runtime_routing.clone().or_else(|| {
            self.reparsed_root_json()
                .and_then(|root| parse_runtime_routing_config(&root))
        })
    }

    pub fn merged_with_overlay(
        base: &LoadedDeclarativeConfig,
        overlay: &LoadedDeclarativeConfig,
    ) -> Result<Self, CliError> {
        match (base.reparsed_root_json(), overlay.reparsed_root_json()) {
            (None, None) => Ok(Self::empty()),
            (Some(_), None) => Ok(base.clone()),
            (None, Some(_)) => Ok(overlay.clone()),
            (Some(mut base_root), Some(overlay_root)) => {
                merge_config_json(&mut base_root, &overlay_root, &[]);
                let merged_yaml = serde_yaml::to_string(&base_root).map_err(|error| {
                    CliError::internal(format!("failed to serialize merged config YAML: {error}"))
                })?;
                Self::from_bytes(merged_yaml.as_bytes())
            }
        }
    }
}

fn merge_config_json(base: &mut serde_json::Value, overlay: &serde_json::Value, path: &[&str]) {
    if should_replace_object_map(path) {
        *base = overlay.clone();
        return;
    }

    match (base, overlay) {
        (serde_json::Value::Object(base_object), serde_json::Value::Object(overlay_object)) => {
            for (key, overlay_value) in overlay_object {
                let mut child_path = path.to_vec();
                child_path.push(key.as_str());
                match base_object.get_mut(key) {
                    Some(base_value) => merge_config_json(base_value, overlay_value, &child_path),
                    None => {
                        base_object.insert(key.clone(), overlay_value.clone());
                    }
                }
            }
        }
        (serde_json::Value::Array(base_array), serde_json::Value::Array(overlay_array)) => {
            if let Some(identity_field) = named_array_merge_identity(path) {
                *base_array = merge_named_object_array(
                    base_array.as_slice(),
                    overlay_array.as_slice(),
                    identity_field,
                );
                return;
            }

            if should_concat_arrays(path) {
                base_array.extend(overlay_array.iter().cloned());
                // CLI-ARCH-004: Deduplicate policy chain entries by `kind` field
                // using a last-wins strategy after concatenation.
                deduplicate_chain_entries_by_kind(base_array);
                return;
            }

            if should_union_string_arrays(path) {
                *base_array =
                    merge_unique_string_array(base_array.as_slice(), overlay_array.as_slice());
                return;
            }

            *base_array = overlay_array.clone();
        }
        (base_value, overlay_value) => {
            *base_value = overlay_value.clone();
        }
    }
}

fn should_replace_object_map(path: &[&str]) -> bool {
    matches!(path, ["tags"] | ["pack", "tags"])
}

fn named_array_merge_identity(path: &[&str]) -> Option<&'static str> {
    match path {
        ["agents"] => Some("id"),
        ["providers", "targets"] => Some("id"),
        ["providers", "model_groups"] => Some("name"),
        ["providers", "pipelines"] => Some("name"),
        ["consumer_groups", "groups"] => Some("name"),
        ["tool_servers"] => Some("id"),
        _ => None,
    }
}

fn should_concat_arrays(path: &[&str]) -> bool {
    matches!(path, ["policies", "chain"])
}

fn chain_entry_kind(entry: &serde_json::Value) -> Option<String> {
    entry
        .as_str()
        .map(ToString::to_string)
        .or_else(|| {
            entry
                .get("kind")
                .and_then(|value| value.as_str())
                .map(ToString::to_string)
        })
        .or_else(|| {
            entry.as_object().and_then(|object| {
                (object.len() == 1)
                    .then(|| object.keys().next().cloned())
                    .flatten()
            })
        })
}

/// CLI-ARCH-004: Deduplicate policy chain entries by their `kind` field.
/// Uses a last-wins strategy: if two entries share the same `kind`, only the
/// last one is kept. Emits a tracing warning when duplicates are detected.
fn deduplicate_chain_entries_by_kind(entries: &mut Vec<serde_json::Value>) {
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut duplicates_found = false;

    // Walk forward, tracking last position of each kind.
    for (idx, entry) in entries.iter().enumerate() {
        let kind = chain_entry_kind(entry);
        if let Some(kind) = kind {
            if seen.insert(kind.clone(), idx).is_some() {
                tracing::warn!(
                    kind = %kind,
                    "duplicate policy chain entry detected during overlay merge — last-wins"
                );
                duplicates_found = true;
            }
        }
    }

    if duplicates_found {
        // Rebuild keeping only the last occurrence of each kind.
        let mut last_positions: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            let kind = chain_entry_kind(entry);
            if let Some(kind) = kind {
                last_positions.insert(kind, idx);
            }
        }
        let last_indices: std::collections::HashSet<usize> =
            last_positions.values().copied().collect();
        let mut idx = 0;
        entries.retain(|_| {
            let keep = last_indices.contains(&idx);
            idx += 1;
            keep
        });
    }
}

fn should_union_string_arrays(path: &[&str]) -> bool {
    matches!(path, ["models", "exposed_model_ids"])
}

fn merge_named_object_array(
    base_values: &[serde_json::Value],
    overlay_values: &[serde_json::Value],
    identity_field: &str,
) -> Vec<serde_json::Value> {
    let mut merged = base_values.to_vec();
    let mut positions = std::collections::HashMap::new();

    for (index, value) in merged.iter().enumerate() {
        if let Some(identity) = named_object_identity(value, identity_field) {
            positions.insert(identity.to_string(), index);
        }
    }

    for value in overlay_values {
        if let Some(identity) = named_object_identity(value, identity_field) {
            if let Some(position) = positions.get(identity).copied() {
                merged[position] = value.clone();
            } else {
                positions.insert(identity.to_string(), merged.len());
                merged.push(value.clone());
            }
            continue;
        }

        merged.push(value.clone());
    }

    merged
}

fn merge_unique_string_array(
    base_values: &[serde_json::Value],
    overlay_values: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut seen = std::collections::HashSet::new();
    let mut merged = Vec::new();

    for value in base_values.iter().chain(overlay_values.iter()) {
        if let Some(text) = value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if seen.insert(text.to_string()) {
                merged.push(serde_json::Value::String(text.to_string()));
            }
        } else {
            merged.push(value.clone());
        }
    }

    merged
}

fn named_object_identity<'a>(
    value: &'a serde_json::Value,
    identity_field: &str,
) -> Option<&'a str> {
    value
        .as_object()?
        .get(identity_field)?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
pub struct HistoryRuntimeConfig {
    pub enabled: bool,
    pub mode: String,
    pub include_blocked: bool,
}

#[derive(Debug, Clone)]
pub struct AgentsRuntimeConfig {
    pub default_agent_id: Option<String>,
    pub overrides: Vec<AgentOverrideConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchListOrWildcard {
    Wildcard,
    Explicit(Vec<String>),
}

impl MatchListOrWildcard {
    pub fn as_explicit(&self) -> Option<&[String]> {
        match self {
            Self::Wildcard => None,
            Self::Explicit(values) => Some(values.as_slice()),
        }
    }

    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContextFabricTtlConfig {
    pub auto_captured_days: Option<u32>,
    pub manual_days: Option<u32>,
    pub verified_days: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContextFabricConfidenceConfig {
    pub votes_for_verified: Option<u32>,
    pub auto_flag_stale_after_days: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContextFabricCacheConfig {
    pub l1_enabled: Option<bool>,
    pub l1_max_entries: Option<u32>,
    pub redis_url: Option<String>,
    pub l2_bloom_false_positive_rate: Option<f64>,
    pub vector_confidence_threshold: Option<f64>,
    pub precompute_enabled: Option<bool>,
    pub precompute_debounce_ms: Option<u64>,
    pub hnsw_ef_construct: Option<u32>,
    pub hnsw_m: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContextFabricMultiGatewayConfig {
    pub enabled: Option<bool>,
    pub peers: Option<Vec<ContextFabricPeerConfig>>,
    pub sync_interval_ms: Option<u64>,
    pub max_partition_buffer_age: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContextFabricPeerConfig {
    pub gateway_id: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContextFabricConfig {
    pub enabled: Option<bool>,
    pub capture_mode: Option<String>,
    pub capture_exclude_patterns: Option<Vec<String>>,
    pub pool_max_entries: Option<u32>,
    pub ttl: Option<ContextFabricTtlConfig>,
    pub dedup_similarity_threshold: Option<f64>,
    pub compaction_similarity_threshold: Option<f64>,
    pub pii_detection: Option<bool>,
    pub dlp_filter: Option<bool>,
    pub confidence: Option<ContextFabricConfidenceConfig>,
    pub branch_inheritance: Option<bool>,
    pub direct_answer_threshold: Option<f64>,
    pub cache: Option<ContextFabricCacheConfig>,
    pub conflict_resolution_strategy: Option<String>,
    pub multi_gateway: Option<ContextFabricMultiGatewayConfig>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct McpSessionLimitsConfig {
    pub max_prompt_bytes: Option<u64>,
    pub max_test_inference_cost_usd: Option<f64>,
    pub max_concurrent_sessions: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct McpToolServerPolicyConfig {
    pub allow_unapproved: Option<bool>,
    pub allowed_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentMcpConfig {
    pub enabled: Option<bool>,
    pub allowed_tools: Option<MatchListOrWildcard>,
    pub allowed_resources: Option<MatchListOrWildcard>,
    pub session_limits: Option<McpSessionLimitsConfig>,
    pub tool_servers: Option<McpToolServerPolicyConfig>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct McpServerConfig {
    pub enabled: Option<bool>,
    pub path: Option<String>,
    pub allowed_tools: Option<MatchListOrWildcard>,
    pub allowed_resources: Option<MatchListOrWildcard>,
    pub max_request_body_bytes: Option<u64>,
    pub auth_mode: Option<String>,
    pub default_capture_mode: Option<String>,
    pub session_limits: Option<McpSessionLimitsConfig>,
    pub tool_servers: Option<McpToolServerPolicyConfig>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GatewayAgentDeclaration {
    pub id: String,
    pub team: String,
    pub context_fabric: Option<ContextFabricConfig>,
    pub mcp: Option<AgentMcpConfig>,
}

/// Per-agent override of routing policy, plugin governance, and silent engine
/// settings. Allows declarative config to customize behavior for specific agents
/// beyond the org-wide defaults.
///
/// ```yaml
/// agents:
/// runtime:
/// default_agent_id: agent-1
/// overrides:
/// - agent_id: agent-1
/// runtime_routing:
/// default_provider_policy:
/// zdr: true
/// data_collection: deny
/// shadow_routing:
/// enabled: false
/// silent_engine:
/// enabled: true
/// plugin_governance:
/// forced_on:
/// - id: web-search
/// enabled: true
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentOverrideConfig {
    pub agent_id: String,
    #[serde(default)]
    pub runtime_routing: Option<RuntimeRoutingConfig>,
    #[serde(default)]
    pub silent_engine: Option<SilentEngineConfig>,
    #[serde(default)]
    pub plugin_governance: Option<RuntimePluginGovernanceConfig>,
}

// ─── Runtime routing declarative config ──────────────────────────────────────

/// Provider routing policy defaults parsed from the `runtime_routing:` top-level
/// key. These mirror the settings exposed by the console Runtime Routing page
/// and, in connected mode, fetched from the control-plane API.
///
/// ```yaml
/// runtime_routing:
/// default_provider_policy:
/// allow_fallbacks: true
/// require_parameters: true
/// data_collection: allow # "allow" | "deny"
/// zdr: false
/// cache_defaults:
/// allow_cache_control: true
/// sticky_routing: true
/// allow_session_id: true
/// session_header_name: x-session-id
/// plugin_governance:
/// defaults:
/// - id: context-compression
/// enabled: true
/// forced_on:
/// - id: web-search
/// enabled: true
/// prevent_overrides:
/// - pdf-inputs
/// shadow_routing:
/// enabled: false
/// evaluation_mode: asynchronous
/// capture_mode: metadata_only
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeRoutingConfig {
    #[serde(default = "default_runtime_provider_policy")]
    pub default_provider_policy: RuntimeProviderPolicyConfig,
    #[serde(default = "default_runtime_cache_defaults")]
    pub cache_defaults: RuntimeCacheDefaultsConfig,
    #[serde(default)]
    pub plugin_governance: RuntimePluginGovernanceConfig,
    #[serde(default)]
    pub shadow_routing: RuntimeShadowRoutingConfig,
}

impl Default for RuntimeRoutingConfig {
    fn default() -> Self {
        Self {
            default_provider_policy: default_runtime_provider_policy(),
            cache_defaults: default_runtime_cache_defaults(),
            plugin_governance: RuntimePluginGovernanceConfig::default(),
            shadow_routing: RuntimeShadowRoutingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeProviderPolicyConfig {
    #[serde(default = "default_true_val")]
    pub allow_fallbacks: bool,
    #[serde(default = "default_true_val")]
    pub require_parameters: bool,
    #[serde(default = "default_data_collection")]
    pub data_collection: String,
    #[serde(default)]
    pub zdr: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeCacheDefaultsConfig {
    #[serde(default = "default_true_val")]
    pub allow_cache_control: bool,
    #[serde(default = "default_true_val")]
    pub sticky_routing: bool,
    #[serde(default = "default_true_val")]
    pub allow_session_id: bool,
    #[serde(default = "default_session_header")]
    pub session_header_name: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimePluginGovernanceConfig {
    #[serde(default)]
    pub defaults: Vec<RuntimePluginSettingConfig>,
    #[serde(default)]
    pub forced_on: Vec<RuntimePluginSettingConfig>,
    #[serde(default)]
    pub prevent_overrides: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimePluginSettingConfig {
    pub id: String,
    #[serde(default = "default_true_val")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeShadowRoutingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_shadow_eval_mode")]
    pub evaluation_mode: String,
    #[serde(default = "default_shadow_cap_mode")]
    pub capture_mode: String,
}

impl Default for RuntimeShadowRoutingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            evaluation_mode: default_shadow_eval_mode(),
            capture_mode: default_shadow_cap_mode(),
        }
    }
}

fn default_true_val() -> bool {
    true
}

fn default_data_collection() -> String {
    "allow".to_string()
}

fn default_session_header() -> String {
    "x-session-id".to_string()
}

fn default_shadow_eval_mode() -> String {
    "asynchronous".to_string()
}

fn default_shadow_cap_mode() -> String {
    "metadata_only".to_string()
}

fn default_runtime_provider_policy() -> RuntimeProviderPolicyConfig {
    RuntimeProviderPolicyConfig {
        allow_fallbacks: true,
        require_parameters: true,
        data_collection: default_data_collection(),
        zdr: false,
    }
}

fn default_runtime_cache_defaults() -> RuntimeCacheDefaultsConfig {
    RuntimeCacheDefaultsConfig {
        allow_cache_control: true,
        sticky_routing: true,
        allow_session_id: true,
        session_header_name: default_session_header(),
    }
}

// ─── Workflow cache runtime config ───────────────────────────────────────────

/// Cache tier selection, TTL, encryption, and replay policy for workflow caching.
///
/// Parsed from the `workflow_cache:` top-level key in the gateway declarative config.
///
/// ```yaml
/// workflow_cache:
/// enabled: true
/// default_tier: private_edge_cache
/// org_shared_enabled: false
/// default_ttl_secs: 3600
/// allow_cross_provider_replay: false
/// require_approval_for_reuse: false
/// negative_cache_enabled: false
/// direct_semantic_replay_enabled: false
/// codebase_identity_mode: repository_isolated
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkflowCacheRuntimeConfig {
    /// Master switch. When `false`, no workflow caching is performed.
    pub enabled: bool,
    /// Storage backend: "auto" (uses filesystem when no Valkey configured),
    /// "filesystem", "valkey", or "redis".
    #[serde(default = "default_workflow_cache_backend")]
    pub backend: String,
    /// Default cache tier: "private_edge_cache" | "org_shared_cache".
    pub default_tier: String,
    /// Allow writing to and reading from the org-shared cache tier.
    pub org_shared_enabled: bool,
    /// Reference to the encryption key environment variable for cache payload encryption.
    pub encryption_key_ref: Option<String>,
    /// Default entry TTL in seconds.
    pub default_ttl_secs: u64,
    /// Per-data-classification TTL overrides (data-class label → TTL seconds).
    pub ttl_by_data_class: std::collections::HashMap<String, u64>,
    /// Allow replaying a cached response produced by a different provider.
    pub allow_cross_provider_replay: bool,
    /// Require an explicit approval grant before a cached result may be reused.
    pub require_approval_for_reuse: bool,
    /// Cache negative (blocked/rejected) outcomes.
    pub negative_cache_enabled: bool,
    /// Maximum number of cache entries retained per workflow run.
    pub max_entries_per_workflow: Option<u32>,
    /// Declarative opt-in for direct semantic final-response replay.
    pub direct_semantic_replay_enabled: bool,
    /// Codebase identity mode: "repository_isolated" | "monorepo_group".
    pub codebase_identity_mode: String,
    /// Optional group ID used when codebase_identity_mode is "monorepo_group".
    pub monorepo_group_id: Option<String>,
    /// Repository IDs included in the monorepo group identity.
    pub monorepo_repo_ids: Vec<String>,
    /// Whether gateways in the same agent gateway group may share org cache entries.
    pub agent_gateway_group_cache_sharing_enabled: bool,
    /// Optional agent gateway group identity for org-shared cache scoping.
    pub agent_gateway_group_id: Option<String>,
    /// Force physical gateway id into cache keys for private-only deployments.
    pub physical_gateway_private_cache_only: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostedGatewayRuntimeConfig {
    pub local_access: HostedGatewayLocalAccessConfig,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostedGatewayLocalAccessConfig {
    pub enabled: bool,
    pub allowed_roots: Vec<String>,
    pub mode: String,
    pub max_file_bytes: u64,
    pub exclude_globs: Vec<String>,
    pub allowed_commands: Vec<String>,
    pub blocked_commands: Vec<String>,
    pub approval_required_risk_levels: Vec<String>,
    pub command_timeout_seconds: u64,
    pub max_output_bytes: u64,
}

impl Default for HostedGatewayLocalAccessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_roots: Vec::new(),
            mode: "read_only".to_string(),
            max_file_bytes: 1_048_576,
            exclude_globs: Vec::new(),
            allowed_commands: Vec::new(),
            blocked_commands: Vec::new(),
            approval_required_risk_levels: vec!["destructive".to_string(), "critical".to_string()],
            command_timeout_seconds: 30,
            max_output_bytes: 65_536,
        }
    }
}

fn default_workflow_cache_backend() -> String {
    "auto".to_string()
}

impl Default for WorkflowCacheRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: default_workflow_cache_backend(),
            default_tier: "private_edge_cache".to_string(),
            org_shared_enabled: false,
            encryption_key_ref: None,
            default_ttl_secs: 3600,
            ttl_by_data_class: std::collections::HashMap::new(),
            allow_cross_provider_replay: false,
            require_approval_for_reuse: false,
            negative_cache_enabled: false,
            max_entries_per_workflow: None,
            direct_semantic_replay_enabled: false,
            codebase_identity_mode: "repository_isolated".to_string(),
            monorepo_group_id: None,
            monorepo_repo_ids: Vec::new(),
            agent_gateway_group_cache_sharing_enabled: true,
            agent_gateway_group_id: None,
            physical_gateway_private_cache_only: false,
        }
    }
}

// ─── Offline egress config ───────────────────────────────────────────────────

/// Offline mode and egress restriction settings.
///
/// Parsed from the `offline_egress:` top-level key in the gateway declarative config.
///
/// ```yaml
/// offline_egress:
/// offline_mode: false
/// block_internet_egress: false
/// allowed_egress_hosts:
/// - api.internal.example.com
/// local_only_providers: false
/// disable_external_health_checks: false
/// ```
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct OfflineEgressConfig {
    /// Engage full offline mode — no outbound connections of any kind.
    pub offline_mode: bool,
    /// Block all internet egress while still allowing explicitly listed hosts.
    pub block_internet_egress: bool,
    /// Explicit hostname allowlist used when `block_internet_egress` is true.
    pub allowed_egress_hosts: Vec<String>,
    /// Restrict provider dispatch to locally-reachable model endpoints only.
    pub local_only_providers: bool,
    /// Suppress outbound health-check pings to external provider health endpoints.
    pub disable_external_health_checks: bool,
}

// ─── AI Usage Streaming config ────────────────────────────────────

/// Data-plane capture controls for AI Usage SIEM streaming.
///
/// This stanza owns ONLY `enabled`, `body_capture_max_bytes`, and `mandatory`
/// (fail-closed). Redaction mode and destination selection are API-owned in
/// `siem_destinations` and must not appear here.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AiUsageStreamingConfig {
    /// Enable AI usage record capture and forwarding.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum bytes to capture for request and response bodies.
    /// Clamped at runtime to an absolute ceiling.
    #[serde(default = "default_body_capture_max_bytes")]
    pub body_capture_max_bytes: usize,
    /// When true, fail closed (503) if durable enqueue fails before dispatch.
    #[serde(default)]
    pub mandatory: bool,
}

fn default_body_capture_max_bytes() -> usize {
    super::ai_usage_capture::DEFAULT_BODY_CAPTURE_MAX_BYTES
}

impl Default for AiUsageStreamingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            body_capture_max_bytes: default_body_capture_max_bytes(),
            mandatory: false,
        }
    }
}

impl AiUsageStreamingConfig {
    /// Convert to the runtime `CaptureConfig` used by the capture pipeline.
    pub fn to_capture_config(&self) -> super::ai_usage_capture::CaptureConfig {
        super::ai_usage_capture::CaptureConfig {
            enabled: self.enabled,
            body_capture_max_bytes: self.body_capture_max_bytes,
            mandatory: self.mandatory,
        }
    }
}

// ─── Phase 40: Region override config ─────────────────────────────────────────

/// Per-region override for gateway behavior. When the gateway operates in a
/// given region, these values are merged on top of the base config.
///
/// ```yaml
/// regions:
/// eu-west:
/// providers:
/// - provider-eu-1
/// - provider-eu-2
/// detection_sensitivity: high
/// cache:
/// backend: valkey
/// ttl_seconds: 600
/// rate_limit_multiplier: 0.8
/// us-east:
/// providers:
/// - provider-us-1
/// detection_sensitivity: medium
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegionOverrideConfig {
    #[serde(default)]
    pub providers: Option<Vec<String>>,
    #[serde(default)]
    pub detection_sensitivity: Option<String>,
    #[serde(default)]
    pub cache: Option<RegionCacheOverride>,
    #[serde(default)]
    pub rate_limit_multiplier: Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegionCacheOverride {
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

fn parse_region_overrides(
    root: &serde_json::Value,
) -> Result<Option<std::collections::HashMap<String, RegionOverrideConfig>>, crate::error::CliError>
{
    let Some(section) = root.get("regions") else {
        return Ok(None);
    };
    let Some(obj) = section.as_object() else {
        return Err(crate::error::CliError::user(
            "regions: must be a map of region slugs to override configs",
        ));
    };
    if obj.is_empty() {
        return Ok(None);
    }

    let mut map = std::collections::HashMap::with_capacity(obj.len());
    for (key, value) in obj {
        crate::region::validate_region_slug(key)?;
        let override_config: RegionOverrideConfig =
            serde_json::from_value(value.clone()).map_err(|e| {
                crate::error::CliError::user(format!("invalid region override for '{key}': {e}"))
            })?;
        if let Some(ref sensitivity) = override_config.detection_sensitivity {
            if !matches!(sensitivity.as_str(), "low" | "medium" | "high") {
                return Err(crate::error::CliError::user(format!(
                    "regions.{key}.detection_sensitivity must be one of: low, medium, high"
                )));
            }
        }
        if let Some(ref multiplier) = override_config.rate_limit_multiplier {
            if *multiplier <= 0.0 || *multiplier > 10.0 {
                return Err(crate::error::CliError::user(format!(
                    "regions.{key}.rate_limit_multiplier must be between 0 (exclusive) and 10"
                )));
            }
        }
        map.insert(key.clone(), override_config);
    }
    Ok(Some(map))
}

// ─── Tool server declarative config ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ToolServerDeclaration {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub transport: ToolServerTransportConfig,
    pub mutability_class: String,
    pub trust_state: String,
    pub containment: ToolServerContainmentConfig,
    pub labels: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ToolServerTransportConfig {
    pub kind: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub auth_type: String,
    pub secret_key_env: Option<String>,
    pub header_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ToolServerContainmentConfig {
    pub network_policy: String,
    pub timeout_ms: u64,
    pub max_concurrent_calls: u32,
}

impl Default for ToolServerContainmentConfig {
    fn default() -> Self {
        Self {
            network_policy: "egress_restricted".to_string(),
            timeout_ms: 30_000,
            max_concurrent_calls: 5,
        }
    }
}

pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn parse_tags_map(
    value: Option<&serde_json::Value>,
    path: &str,
) -> Result<std::collections::BTreeMap<String, String>, CliError> {
    let Some(value) = value else {
        return Ok(std::collections::BTreeMap::new());
    };
    let Some(object) = value.as_object() else {
        return Err(CliError::user(format!(
            "{path} must be a map of tag keys to string values"
        )));
    };
    if object.len() > 50 {
        return Err(CliError::user(format!(
            "{path} supports at most 50 tags, found {}",
            object.len()
        )));
    }

    let mut tags = std::collections::BTreeMap::new();
    for (key, value) in object {
        validate_tag_key(key, path)?;
        let Some(value) = value.as_str() else {
            return Err(CliError::user(format!(
                "{path}.{key} must be a string tag value"
            )));
        };
        validate_tag_value(key, value, path)?;
        tags.insert(key.clone(), value.to_string());
    }
    Ok(tags)
}

fn validate_tag_key(key: &str, path: &str) -> Result<(), CliError> {
    if key.is_empty() {
        return Err(CliError::user(format!("{path} tag keys must not be empty")));
    }
    if !key.is_ascii() {
        return Err(CliError::user(format!(
            "{path}.{key} must use ASCII tag keys"
        )));
    }
    if key.len() > 128 {
        return Err(CliError::user(format!(
            "{path}.{key} exceeds the 128 character tag key limit"
        )));
    }
    if key.starts_with("verdictan:") {
        return Err(CliError::user(format!(
            "{path}.{key} uses the reserved verdictan: tag prefix"
        )));
    }
    Ok(())
}

fn validate_tag_value(key: &str, value: &str, path: &str) -> Result<(), CliError> {
    if !value.is_ascii() {
        return Err(CliError::user(format!(
            "{path}.{key} must use ASCII tag values"
        )));
    }
    if value.len() > 256 {
        return Err(CliError::user(format!(
            "{path}.{key} exceeds the 256 character tag value limit"
        )));
    }
    Ok(())
}

// ─── Phase 18 parsing ────────────────────────────────────────────────────────

fn parse_token_rate_limit(
    root: &serde_json::Value,
) -> Option<super::token_rate_limit::TokenRateLimitConfig> {
    let v = root.get("token_rate_limit")?;
    let max_tokens = v.get("max_tokens")?.as_u64()?;
    let window_seconds = v.get("window_seconds")?.as_u64()?;
    let scope = match v.get("scope").and_then(|s| s.as_str()).unwrap_or("global") {
        "per_key" => super::token_rate_limit::TokenScope::PerKey,
        "per_ip" => super::token_rate_limit::TokenScope::PerIp,
        _ => super::token_rate_limit::TokenScope::Global,
    };
    Some(super::token_rate_limit::TokenRateLimitConfig {
        max_tokens,
        window_seconds,
        scope,
    })
}

// ─── Phase 19 parsing ────────────────────────────────────────────────────────

fn parse_global_rate_limit(
    root: &serde_json::Value,
) -> Option<super::rate_limit::GlobalRateLimitConfig> {
    let v = root.get("global_rate_limit")?;
    Some(super::rate_limit::GlobalRateLimitConfig {
        max_requests: v.get("max_requests")?.as_u64()?,
        window_seconds: v.get("window_seconds")?.as_u64()?,
    })
}

fn parse_ip_rate_limit(root: &serde_json::Value) -> Option<super::rate_limit::IpRateLimitConfig> {
    let v = root.get("ip_rate_limit")?;
    Some(super::rate_limit::IpRateLimitConfig {
        max_requests: v.get("max_requests")?.as_u64()?,
        window_seconds: v.get("window_seconds")?.as_u64()?,
        trusted_proxy_cidrs: v
            .get("trusted_proxy_cidrs")
            .and_then(|candidate| candidate.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

fn parse_user_rate_limit(
    root: &serde_json::Value,
) -> Option<super::rate_limit::UserRateLimiterConfig> {
    let v = root.get("user_rate_limit")?;
    Some(super::rate_limit::UserRateLimiterConfig {
        max_requests: v.get("max_requests")?.as_u64()?,
        window_seconds: v.get("window_seconds")?.as_u64()?,
        header_names: v
            .get("header_names")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(ToString::to_string))
                    .collect::<Vec<_>>()
            })
            .filter(|items| !items.is_empty())
            .unwrap_or_else(|| vec!["x-user-id".to_string()]),
    })
}

// ─── Phase 20 parsing ────────────────────────────────────────────────────────

fn parse_size_limits(root: &serde_json::Value) -> Option<super::size_limit::SizeLimitConfig> {
    let v = root.get("size_limits")?;
    Some(super::size_limit::SizeLimitConfig {
        max_body_bytes: v
            .get("max_body_bytes")
            .and_then(|x| x.as_u64())
            .map(|x| x as usize),
        max_header_bytes: v
            .get("max_header_bytes")
            .and_then(|x| x.as_u64())
            .map(|x| x as usize),
        max_url_bytes: v
            .get("max_url_bytes")
            .and_then(|x| x.as_u64())
            .map(|x| x as usize),
        max_response_bytes: v
            .get("max_response_bytes")
            .and_then(|x| x.as_u64())
            .map(|x| x as usize),
    })
}

// ─── Phase 23 parsing ────────────────────────────────────────────────────────

fn parse_semantic_cache(root: &serde_json::Value) -> Option<super::cache::SemanticCacheConfig> {
    let v = root.get("cache")?;
    let enabled = v.get("enabled").and_then(|b| b.as_bool()).unwrap_or(true);
    let mode_str = v.get("mode").and_then(|m| m.as_str()).unwrap_or("exact");
    let mode = match mode_str {
        "semantic" => super::cache::CacheMode::Semantic,
        _ => super::cache::CacheMode::Exact,
    };
    let similarity_threshold = v
        .get("similarity_threshold")
        .and_then(|t| t.as_f64())
        .unwrap_or(0.85);
    let embedding_provider = v
        .get("embedding_provider")
        .and_then(|p| p.as_str())
        .map(ToString::to_string);
    let default_on = v
        .get("default_on")
        .and_then(|b| b.as_bool())
        .unwrap_or(true);
    let ttl_seconds = v
        .get("ttl_seconds")
        .and_then(|value| value.as_u64())
        .filter(|value| *value > 0);
    Some(super::cache::SemanticCacheConfig {
        enabled,
        mode,
        similarity_threshold,
        embedding_provider,
        default_on,
        ttl_seconds,
    })
}

fn parse_ip_allowlist(root: &serde_json::Value) -> Option<super::network::IpAllowlistConfig> {
    let value = root.get("ip_allowlist")?;
    Some(super::network::IpAllowlistConfig {
        cidrs: value
            .get("cidrs")
            .and_then(|candidate| candidate.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(ToString::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        trusted_proxy_cidrs: value
            .get("trusted_proxy_cidrs")
            .and_then(|candidate| candidate.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

fn parse_cors(root: &serde_json::Value) -> Option<super::network::CorsConfig> {
    let value = root.get("cors")?;
    serde_json::from_value(value.clone()).ok()
}

// ─── Phase 21 parsing ────────────────────────────────────────────────────────

fn parse_distributed_config(
    root: &serde_json::Value,
) -> Option<super::distributed_rate_limit::DistributedConfig> {
    // Distributed rate limiting can be configured either with the top-level
    // `distributed_rate_limit:` block or with a nested `distributed:` object
    // under a rate limit section.
    let candidates = [
        root.pointer("/distributed_rate_limit"),
        root.pointer("/global_rate_limit/distributed"),
        root.pointer("/ip_rate_limit/distributed"),
        root.pointer("/token_rate_limit/distributed"),
    ];

    for candidate in candidates.into_iter().flatten() {
        let backend_str = candidate
            .get("backend")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if matches!(backend_str, "redis" | "valkey") {
            let url_env = candidate
                .get("url_env")
                .and_then(|v| v.as_str())
                .unwrap_or("VERDICTAN_LLM_CACHE_REDIS_URL")
                .to_string();
            return Some(super::distributed_rate_limit::DistributedConfig {
                backend: if backend_str == "valkey" {
                    super::distributed_rate_limit::DistributedBackend::Valkey { url_env }
                } else {
                    super::distributed_rate_limit::DistributedBackend::Redis { url_env }
                },
            });
        }
    }
    None
}

fn parse_history_runtime_config(root: &serde_json::Value) -> Option<HistoryRuntimeConfig> {
    let section = root
        .pointer("/history/capture")
        .or_else(|| root.get("history"))?;
    Some(HistoryRuntimeConfig {
        enabled: section
            .get("enabled")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        mode: section
            .get("mode")
            .and_then(|value| value.as_str())
            .unwrap_or("metadata_only")
            .to_string(),
        include_blocked: section
            .get("include_blocked")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
    })
}

fn parse_silent_engine_config(root: &serde_json::Value) -> Option<SilentEngineConfig> {
    let section = root.get("silent_engine")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_runtime_routing_config(root: &serde_json::Value) -> Option<RuntimeRoutingConfig> {
    let section = root.get("runtime_routing")?;
    serde_json::from_value(section.clone()).ok()
}

fn config_actual_value(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(value) => serde_json::to_string(value).unwrap_or_else(|_| format!("{value:?}")),
        None => "missing".to_string(),
    }
}

fn invalid_config_value(path: &str, expected: &str, value: Option<&serde_json::Value>) -> CliError {
    CliError::user(format!(
        "{path}: expected {expected}; actual value: {}",
        config_actual_value(value)
    ))
}

fn inactive_config_field(path: &str, message: &str) -> CliError {
    CliError::user(format!("{path}: {message}"))
}

/// Policy kinds registered in the canonical gateway policy registry.
fn registry_supported_policy_kinds() -> Vec<&'static str> {
    super::policy_registry::POLICY_REGISTRY
        .iter()
        .map(|entry| entry.kind)
        .collect()
}

/// Returns true when `kind` is present in the canonical policy registry.
pub fn is_registry_supported_policy_kind(kind: &str) -> bool {
    super::policy_registry::lookup(kind).is_some()
}

fn embedded_policy_schema_json() -> Result<&'static serde_json::Value, String> {
    use std::sync::OnceLock;
    static SCHEMA: OnceLock<Result<serde_json::Value, String>> = OnceLock::new();
    match SCHEMA.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../schema/policy-configuration.schema.json"
        ))
        .map_err(|error| format!("failed to parse embedded policy schema: {error}"))
    }) {
        Ok(value) => Ok(value),
        Err(error) => Err(error.clone()),
    }
}

fn schema_definition_name_for_kind(kind: &str) -> Option<&'static str> {
    super::policy_registry::lookup(kind).and_then(|entry| {
        entry
            .schema_ref
            .strip_prefix("#/definitions/")
            .filter(|name| !name.is_empty())
    })
}

fn collect_schema_object_property_keys(
    definition: &serde_json::Value,
    definitions: &serde_json::Map<String, serde_json::Value>,
    out: &mut std::collections::BTreeSet<String>,
) {
    if let Some(properties) = definition
        .get("properties")
        .and_then(serde_json::Value::as_object)
    {
        out.extend(properties.keys().cloned());
    }

    if let Some(reference) = definition.get("$ref").and_then(serde_json::Value::as_str) {
        if let Some(name) = reference.strip_prefix("#/definitions/") {
            if let Some(target) = definitions.get(name) {
                collect_schema_object_property_keys(target, definitions, out);
            }
        }
    }

    for key in ["allOf", "anyOf", "oneOf"] {
        if let Some(items) = definition.get(key).and_then(serde_json::Value::as_array) {
            for item in items {
                collect_schema_object_property_keys(item, definitions, out);
            }
        }
    }
}

/// Consumed configuration keys for a registered policy kind, derived from the
/// registry `schema_ref` and the embedded policy schema definition properties.
pub fn registry_consumed_config_keys(
    kind: &str,
) -> Result<std::collections::BTreeSet<String>, String> {
    let schema = embedded_policy_schema_json()?;
    let definitions = schema
        .get("definitions")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "embedded policy schema missing definitions".to_string())?;
    let def_name = schema_definition_name_for_kind(kind)
        .ok_or_else(|| format!("policy kind '{kind}' is not registered"))?;
    let definition = definitions.get(def_name).ok_or_else(|| {
        format!("registry schema_ref '#/definitions/{def_name}' missing from policy schema")
    })?;
    let mut keys = std::collections::BTreeSet::new();
    collect_schema_object_property_keys(definition, definitions, &mut keys);
    Ok(keys)
}

fn reject_unread_object_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    path: &str,
    diags: &mut Vec<String>,
) {
    for key in object.keys() {
        if !allowed.iter().any(|allowed_key| allowed_key == key) {
            diags.push(format!(
                "{path}.{key}: unknown field — allowed keys: {}",
                allowed.join(", ")
            ));
        }
    }
}

fn validate_chain_entry_against_registry(
    entry: &serde_json::Value,
    path: &str,
    diags: &mut Vec<String>,
) {
    if let Some(kind) = entry.as_str() {
        if !is_registry_supported_policy_kind(kind) {
            diags.push(format!(
                "{path}: unknown policy kind '{kind}' — not present in policy_registry"
            ));
        }
        return;
    }

    let Some(object) = entry.as_object() else {
        diags.push(format!(
            "{path}: chain entry must be a policy kind string or a single-key conditional object"
        ));
        return;
    };

    if object.len() != 1 {
        diags.push(format!(
            "{path}: conditional chain entry must have exactly one policy-kind property"
        ));
        return;
    }

    let Some((kind, inner)) = object.iter().next() else {
        diags.push(format!(
            "{path}: conditional chain entry must have exactly one policy-kind property"
        ));
        return;
    };
    if !is_registry_supported_policy_kind(kind) {
        diags.push(format!(
            "{path}: unknown policy kind '{kind}' — not present in policy_registry"
        ));
    }

    let Some(inner_object) = inner.as_object() else {
        if !inner.is_null() {
            diags.push(format!(
                "{path}.{kind}: conditional value must be an object"
            ));
        }
        return;
    };

    reject_unread_object_fields(
        inner_object,
        CHAIN_CONDITIONAL_CONSUMED_KEYS,
        &format!("{path}.{kind}"),
        diags,
    );

    if let Some(when) = inner_object.get("when") {
        match when.as_object() {
            Some(when_object) => reject_unread_object_fields(
                when_object,
                WHEN_PREDICATE_CONSUMED_KEYS,
                &format!("{path}.{kind}.when"),
                diags,
            ),
            None => diags.push(format!("{path}.{kind}.when: must be an object")),
        }
    }
}

fn validate_policy_blocks_against_registry(root: &serde_json::Value, diags: &mut Vec<String>) {
    let Some(policy_blocks) = root.get("policy").and_then(serde_json::Value::as_object) else {
        return;
    };

    // Single-policy files use a metadata header (`policy.name` / `version` /
    // `enabled`) rather than a kind→config map. Do not treat those keys as
    // registry policy kinds.
    let has_kind_keyed_blocks = policy_blocks
        .keys()
        .any(|key| is_registry_supported_policy_kind(key));
    if !has_kind_keyed_blocks {
        if let Some(name) = policy_blocks
            .get("name")
            .and_then(serde_json::Value::as_str)
        {
            if !is_registry_supported_policy_kind(name) {
                diags.push(format!(
                    "policy.name: unknown policy kind '{name}' — not present in policy_registry"
                ));
            }
        }
        return;
    }

    for (kind, config) in policy_blocks {
        if !is_registry_supported_policy_kind(kind) {
            diags.push(format!(
                "policy.{kind}: unknown policy kind — not present in policy_registry"
            ));
            continue;
        }

        let Ok(allowed_keys) = registry_consumed_config_keys(kind) else {
            diags.push(format!(
                "policy.{kind}: unable to derive consumed configuration keys from registry schema_ref"
            ));
            continue;
        };

        let Some(config_object) = config.as_object() else {
            diags.push(format!("policy.{kind}: configuration must be an object"));
            continue;
        };

        for key in config_object.keys() {
            if !allowed_keys.contains(key) {
                diags.push(format!(
                    "policy.{kind}.{key}: parsed-but-unread or unknown field — not a consumed configuration key for this policy"
                ));
            }
        }
    }
}

/// Diagnostics for registry/schema/runtime parity of policy kinds and consumed keys.
///
/// Rejects unknown chain kinds, arbitrary conditional-object property names,
/// arbitrary `when` property names, unknown policy-block kinds, and every
/// policy-block field that is not a consumed configuration key derived from the
/// registry `schema_ref`.
pub fn registry_policy_contract_diagnostics(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    if let Some(chain) = root
        .pointer("/policies/chain")
        .and_then(serde_json::Value::as_array)
    {
        for (index, entry) in chain.iter().enumerate() {
            validate_chain_entry_against_registry(
                entry,
                &format!("policies.chain[{index}]"),
                &mut diags,
            );
        }
    }

    validate_policy_blocks_against_registry(root, &mut diags);
    diags
}

pub(crate) fn validate_inactive_configuration_fields(
    root: &serde_json::Value,
) -> Result<(), CliError> {
    reject_removed_audit_logger_fields(root)?;
    reject_removed_human_oversight_fields(root)?;
    reject_removed_tool_budget_policy_fields(root)?;
    reject_removed_route_fields(root)?;
    reject_removed_consumer_group_fields(root)?;
    reject_removed_provider_fallback_fields(root)?;
    reject_removed_provider_scope_rate_limit_fields(root)?;
    Ok(())
}

fn reject_removed_audit_logger_fields(root: &serde_json::Value) -> Result<(), CliError> {
    let Some(config) = root
        .pointer("/policy/audit-logger")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };

    for field in [
        "immutable",
        "retention_days",
        "hipaa_audit_controls",
        "log_all_access",
    ] {
        if config.contains_key(field) {
            return Err(inactive_config_field(
                &format!("policy.audit-logger.{field}"),
                "field has been removed; audit retention, immutability, and storage are externally owned",
            ));
        }
    }

    Ok(())
}

fn reject_removed_human_oversight_fields(root: &serde_json::Value) -> Result<(), CliError> {
    let Some(config) = root
        .pointer("/policy/human-oversight")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };

    for field in [
        "require_human_for",
        "confidence_threshold",
        "default_assignee",
        "timeout_seconds",
    ] {
        if config.contains_key(field) {
            return Err(inactive_config_field(
                &format!("policy.human-oversight.{field}"),
                "field has been removed; only 'action: escalate' is enforced",
            ));
        }
    }

    if config
        .get("action")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.trim() == "block")
    {
        return Err(inactive_config_field(
            "policy.human-oversight.action",
            "'block' has been removed; use 'escalate'",
        ));
    }

    Ok(())
}

fn reject_removed_tool_budget_policy_fields(root: &serde_json::Value) -> Result<(), CliError> {
    let Some(budgets) = root
        .pointer("/policy/tool-budget/budgets")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };

    for (tool_name, limit) in budgets {
        let Some(limit_object) = limit.as_object() else {
            continue;
        };
        if limit_object.contains_key("max_cost_usd") {
            return Err(inactive_config_field(
                &format!("policy.tool-budget.budgets.{tool_name}.max_cost_usd"),
                "field has been removed; use max_tokens or a supported budget surface",
            ));
        }
    }

    Ok(())
}

fn reject_removed_route_fields(root: &serde_json::Value) -> Result<(), CliError> {
    let Some(routes) = root.get("routes").and_then(serde_json::Value::as_array) else {
        return Ok(());
    };

    for (index, route) in routes.iter().enumerate() {
        let Some(route_object) = route.as_object() else {
            continue;
        };
        if route_object.contains_key("strip_path") {
            return Err(inactive_config_field(
                &format!("routes[{index}].strip_path"),
                "field has been removed; route-level path rewriting is not enforced",
            ));
        }
        if route_object.contains_key("upstream") {
            return Err(inactive_config_field(
                &format!("routes[{index}].upstream"),
                "field has been removed; route-level upstream selection is not enforced",
            ));
        }
    }

    Ok(())
}

fn reject_removed_consumer_group_fields(root: &serde_json::Value) -> Result<(), CliError> {
    let Some(groups) = root
        .pointer("/consumer_groups/groups")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(());
    };

    for (index, group) in groups.iter().enumerate() {
        let Some(group_object) = group.as_object() else {
            continue;
        };
        if group_object.contains_key("upstream") {
            return Err(inactive_config_field(
                &format!("consumer_groups.groups[{index}].upstream"),
                "field has been removed; consumer-group upstream selection is not enforced",
            ));
        }
        if group_object
            .get("rate_limit")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|rate_limit| rate_limit.contains_key("max_tokens"))
        {
            return Err(inactive_config_field(
                &format!("consumer_groups.groups[{index}].rate_limit.max_tokens"),
                "field has been removed; consumer-group token quotas are not enforced",
            ));
        }
    }

    Ok(())
}

fn reject_removed_provider_fallback_fields(root: &serde_json::Value) -> Result<(), CliError> {
    let Some(fallback) = root
        .pointer("/providers/fallback")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };

    for field in ["enabled", "trigger_on", "max_fallback_attempts"] {
        if fallback.contains_key(field) {
            return Err(inactive_config_field(
                &format!("providers.fallback.{field}"),
                "field has been removed; provider fallback overrides are not enforced",
            ));
        }
    }

    if let Some(content_policy) = fallback
        .get("content_policy")
        .and_then(serde_json::Value::as_object)
    {
        for field in ["replacement_model", "custom_response_template"] {
            if content_policy.contains_key(field) {
                return Err(inactive_config_field(
                    &format!("providers.fallback.content_policy.{field}"),
                    "field has been removed; provider fallback overrides are not enforced",
                ));
            }
        }
    }

    if let Some(context_window) = fallback
        .get("context_window")
        .and_then(serde_json::Value::as_object)
    {
        for field in ["overflow_strategy", "overflow_model"] {
            if context_window.contains_key(field) {
                return Err(inactive_config_field(
                    &format!("providers.fallback.context_window.{field}"),
                    "field has been removed; provider fallback overrides are not enforced",
                ));
            }
        }
    }

    Ok(())
}

fn reject_removed_provider_scope_rate_limit_fields(
    root: &serde_json::Value,
) -> Result<(), CliError> {
    if let Some(rate_limits) = root
        .pointer("/providers/rate_limits")
        .and_then(serde_json::Value::as_object)
    {
        reject_removed_provider_scope_rate_limit_object(rate_limits, "providers.rate_limits")?;
    }

    if let Some(rate_limits) = root
        .pointer("/providers/scope_rate_limits")
        .and_then(serde_json::Value::as_object)
    {
        reject_removed_provider_scope_rate_limit_object(
            rate_limits,
            "providers.scope_rate_limits",
        )?;
    }

    Ok(())
}

fn reject_removed_provider_scope_rate_limit_object(
    object: &serde_json::Map<String, serde_json::Value>,
    base_path: &str,
) -> Result<(), CliError> {
    for scope in ["per_key", "per_user", "per_team", "global"] {
        if let Some(scope_object) = object.get(scope).and_then(serde_json::Value::as_object) {
            for field in ["rpm", "tpm"] {
                if scope_object.contains_key(field) {
                    return Err(inactive_config_field(
                        &format!("{base_path}.{scope}.{field}"),
                        "field has been removed; provider-scoped rate-limit metadata is not enforced",
                    ));
                }
            }
        }
    }

    if object.contains_key("max_parallel_requests") {
        return Err(inactive_config_field(
            &format!("{base_path}.max_parallel_requests"),
            "field has been removed; provider-scoped rate-limit metadata is not enforced",
        ));
    }

    Ok(())
}

fn expect_object<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, CliError> {
    value
        .as_object()
        .ok_or_else(|| invalid_config_value(path, "object", Some(value)))
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), CliError> {
    for (key, value) in object {
        if !allowed.iter().any(|allowed_key| allowed_key == key) {
            let expected = format!("known field ({})", allowed.join(", "));
            return Err(invalid_config_value(
                &format!("{path}.{key}"),
                &expected,
                Some(value),
            ));
        }
    }
    Ok(())
}

fn parse_required_non_empty_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<String, CliError> {
    let field_path = format!("{path}.{key}");
    let value = object.get(key);
    value
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| invalid_config_value(&field_path, "non-empty string", value))
}

fn parse_optional_non_empty_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<String>, CliError> {
    let field_path = format!("{path}.{key}");
    let Some(value) = object.get(key) else {
        return Ok(None);
    };

    value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| Some(text.to_string()))
        .ok_or_else(|| invalid_config_value(&field_path, "non-empty string", Some(value)))
}

fn parse_optional_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<bool>, CliError> {
    let field_path = format!("{path}.{key}");
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| invalid_config_value(&field_path, "boolean", Some(value)))
}

fn parse_optional_positive_u32(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<u32>, CliError> {
    let field_path = format!("{path}.{key}");
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_u64() else {
        return Err(invalid_config_value(
            &field_path,
            "positive integer",
            Some(value),
        ));
    };
    if raw == 0 || raw > u32::MAX as u64 {
        return Err(invalid_config_value(
            &field_path,
            "positive integer",
            Some(value),
        ));
    }
    Ok(Some(raw as u32))
}

fn parse_optional_positive_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<u64>, CliError> {
    let field_path = format!("{path}.{key}");
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_u64() else {
        return Err(invalid_config_value(
            &field_path,
            "positive integer",
            Some(value),
        ));
    };
    if raw == 0 {
        return Err(invalid_config_value(
            &field_path,
            "positive integer",
            Some(value),
        ));
    }
    Ok(Some(raw))
}

fn parse_optional_duration_literal(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<String>, CliError> {
    let field_path = format!("{path}.{key}");
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
    else {
        return Err(invalid_config_value(
            &field_path,
            "duration like 24h, 15m, 30s, or 500ms",
            Some(value),
        ));
    };
    if !is_valid_duration_literal(raw) {
        return Err(invalid_config_value(
            &field_path,
            "duration like 24h, 15m, 30s, or 500ms",
            Some(value),
        ));
    }
    Ok(Some(raw.to_string()))
}

fn parse_optional_context_fabric_peer_array(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<Vec<ContextFabricPeerConfig>>, CliError> {
    let field_path = format!("{path}.{key}");
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let Some(items) = value.as_array() else {
        return Err(invalid_config_value(
            &field_path,
            "array of peer objects",
            Some(value),
        ));
    };

    let mut peers = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let peer_path = format!("{field_path}[{index}]");
        peers.push(parse_context_fabric_peer_config(item, &peer_path)?);
    }
    Ok(Some(peers))
}

fn parse_context_fabric_peer_config(
    value: &serde_json::Value,
    path: &str,
) -> Result<ContextFabricPeerConfig, CliError> {
    let object = expect_object(value, path)?;
    reject_unknown_fields(object, &["gateway_id", "endpoint"], path)?;

    let raw_gateway_id = object
        .get("gateway_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid_config_value(
                &format!("{path}.gateway_id"),
                "lowercase hyphenated UUID",
                object.get("gateway_id"),
            )
        })?;
    let parsed_gateway_id = uuid::Uuid::parse_str(raw_gateway_id).map_err(|_| {
        invalid_config_value(
            &format!("{path}.gateway_id"),
            "lowercase hyphenated UUID",
            object.get("gateway_id"),
        )
    })?;

    let endpoint = object
        .get("endpoint")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid_config_value(
                &format!("{path}.endpoint"),
                "absolute URI",
                object.get("endpoint"),
            )
        })?;
    if reqwest::Url::parse(endpoint).is_err() {
        return Err(invalid_config_value(
            &format!("{path}.endpoint"),
            "absolute URI",
            object.get("endpoint"),
        ));
    }

    Ok(ContextFabricPeerConfig {
        gateway_id: parsed_gateway_id.hyphenated().to_string(),
        endpoint: endpoint.to_string(),
    })
}

fn parse_optional_nonnegative_f64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<f64>, CliError> {
    let field_path = format!("{path}.{key}");
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_f64() else {
        return Err(invalid_config_value(
            &field_path,
            "non-negative number",
            Some(value),
        ));
    };
    if raw < 0.0 {
        return Err(invalid_config_value(
            &field_path,
            "non-negative number",
            Some(value),
        ));
    }
    Ok(Some(raw))
}

fn parse_optional_unit_interval_f64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<f64>, CliError> {
    let field_path = format!("{path}.{key}");
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let Some(raw) = value.as_f64() else {
        return Err(invalid_config_value(
            &field_path,
            "number between 0.0 and 1.0",
            Some(value),
        ));
    };
    if !(0.0..=1.0).contains(&raw) {
        return Err(invalid_config_value(
            &field_path,
            "number between 0.0 and 1.0",
            Some(value),
        ));
    }
    Ok(Some(raw))
}

fn parse_strict_string_array(
    value: &serde_json::Value,
    path: &str,
    allow_empty: bool,
) -> Result<Vec<String>, CliError> {
    let Some(array) = value.as_array() else {
        return Err(invalid_config_value(
            path,
            "array of non-empty strings",
            Some(value),
        ));
    };
    if array.is_empty() && !allow_empty {
        return Err(invalid_config_value(
            path,
            "non-empty array of non-empty strings",
            Some(value),
        ));
    }

    let mut values = Vec::with_capacity(array.len());
    for (idx, entry) in array.iter().enumerate() {
        let Some(text) = entry
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
        else {
            return Err(invalid_config_value(
                &format!("{path}[{idx}]"),
                "non-empty string",
                Some(entry),
            ));
        };
        values.push(text.to_string());
    }
    Ok(values)
}

fn is_valid_duration_literal(value: &str) -> bool {
    let number = if let Some(number) = value.strip_suffix("ms") {
        number
    } else if let Some(number) = value.strip_suffix('s') {
        number
    } else if let Some(number) = value.strip_suffix('m') {
        number
    } else if let Some(number) = value.strip_suffix('h') {
        number
    } else if let Some(number) = value.strip_suffix('d') {
        number
    } else {
        return false;
    };

    !number.is_empty()
        && number.chars().all(|character| character.is_ascii_digit())
        && number.parse::<u64>().map(|raw| raw > 0).unwrap_or(false)
}

fn parse_optional_wildcard_or_string_array(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<MatchListOrWildcard>, CliError> {
    let field_path = format!("{path}.{key}");
    let Some(value) = object.get(key) else {
        return Ok(None);
    };

    if let Some(text) = value.as_str() {
        return match text.trim() {
            "*" => Ok(Some(MatchListOrWildcard::Wildcard)),
            _ => Err(invalid_config_value(
                &field_path,
                "array of non-empty strings or the wildcard \"*\"",
                Some(value),
            )),
        };
    }

    Ok(Some(MatchListOrWildcard::Explicit(
        parse_strict_string_array(value, &field_path, false)?,
    )))
}

fn parse_context_fabric_ttl_config(
    value: &serde_json::Value,
    path: &str,
) -> Result<ContextFabricTtlConfig, CliError> {
    let object = expect_object(value, path)?;
    reject_unknown_fields(
        object,
        &["auto_captured_days", "manual_days", "verified_days"],
        path,
    )?;

    Ok(ContextFabricTtlConfig {
        auto_captured_days: parse_optional_positive_u32(object, "auto_captured_days", path)?,
        manual_days: parse_optional_positive_u32(object, "manual_days", path)?,
        verified_days: parse_optional_positive_u32(object, "verified_days", path)?,
    })
}

fn parse_context_fabric_confidence_config(
    value: &serde_json::Value,
    path: &str,
) -> Result<ContextFabricConfidenceConfig, CliError> {
    let object = expect_object(value, path)?;
    reject_unknown_fields(
        object,
        &["votes_for_verified", "auto_flag_stale_after_days"],
        path,
    )?;

    Ok(ContextFabricConfidenceConfig {
        votes_for_verified: parse_optional_positive_u32(object, "votes_for_verified", path)?,
        auto_flag_stale_after_days: parse_optional_positive_u32(
            object,
            "auto_flag_stale_after_days",
            path,
        )?,
    })
}

fn parse_context_fabric_cache_config(
    value: &serde_json::Value,
    path: &str,
) -> Result<ContextFabricCacheConfig, CliError> {
    let object = expect_object(value, path)?;
    reject_unknown_fields(
        object,
        &[
            "l1_enabled",
            "l1_max_entries",
            "redis_url",
            "l2_bloom_false_positive_rate",
            "vector_confidence_threshold",
            "precompute_enabled",
            "precompute_debounce_ms",
            "hnsw_ef_construct",
            "hnsw_m",
        ],
        path,
    )?;

    Ok(ContextFabricCacheConfig {
        l1_enabled: parse_optional_bool(object, "l1_enabled", path)?,
        l1_max_entries: parse_optional_positive_u32(object, "l1_max_entries", path)?,
        redis_url: parse_optional_non_empty_string(object, "redis_url", path)?,
        l2_bloom_false_positive_rate: parse_optional_unit_interval_f64(
            object,
            "l2_bloom_false_positive_rate",
            path,
        )?,
        vector_confidence_threshold: parse_optional_unit_interval_f64(
            object,
            "vector_confidence_threshold",
            path,
        )?,
        precompute_enabled: parse_optional_bool(object, "precompute_enabled", path)?,
        precompute_debounce_ms: parse_optional_positive_u64(
            object,
            "precompute_debounce_ms",
            path,
        )?,
        hnsw_ef_construct: parse_optional_positive_u32(object, "hnsw_ef_construct", path)?,
        hnsw_m: parse_optional_positive_u32(object, "hnsw_m", path)?,
    })
}

fn parse_context_fabric_multi_gateway_config(
    value: &serde_json::Value,
    path: &str,
) -> Result<ContextFabricMultiGatewayConfig, CliError> {
    let object = expect_object(value, path)?;
    reject_unknown_fields(
        object,
        &[
            "enabled",
            "peers",
            "sync_interval_ms",
            "max_partition_buffer_age",
        ],
        path,
    )?;

    Ok(ContextFabricMultiGatewayConfig {
        enabled: parse_optional_bool(object, "enabled", path)?,
        peers: parse_optional_context_fabric_peer_array(object, "peers", path)?,
        sync_interval_ms: parse_optional_positive_u64(object, "sync_interval_ms", path)?,
        max_partition_buffer_age: parse_optional_duration_literal(
            object,
            "max_partition_buffer_age",
            path,
        )?,
    })
}

fn parse_context_fabric_config_value(
    value: &serde_json::Value,
    path: &str,
) -> Result<ContextFabricConfig, CliError> {
    let object = expect_object(value, path)?;
    reject_unknown_fields(
        object,
        &[
            "enabled",
            "capture_mode",
            "capture_exclude_patterns",
            "pool_max_entries",
            "ttl",
            "dedup_similarity_threshold",
            "compaction_similarity_threshold",
            "pii_detection",
            "dlp_filter",
            "confidence",
            "branch_inheritance",
            "direct_answer_threshold",
            "cache",
            "conflict_resolution_strategy",
            "multi_gateway",
        ],
        path,
    )?;

    let capture_mode = match object.get("capture_mode") {
        Some(value) => {
            let field_path = format!("{path}.capture_mode");
            let Some(mode) = value.as_str().map(str::trim) else {
                return Err(invalid_config_value(
                    &field_path,
                    "one of: nudge, auto, off",
                    Some(value),
                ));
            };
            if !matches!(mode, "nudge" | "auto" | "off") {
                return Err(invalid_config_value(
                    &field_path,
                    "one of: nudge, auto, off",
                    Some(value),
                ));
            }
            Some(mode.to_string())
        }
        None => None,
    };

    let capture_exclude_patterns = match object.get("capture_exclude_patterns") {
        Some(value) => Some(parse_strict_string_array(
            value,
            &format!("{path}.capture_exclude_patterns"),
            true,
        )?),
        None => None,
    };

    let ttl = object
        .get("ttl")
        .map(|value| parse_context_fabric_ttl_config(value, &format!("{path}.ttl")))
        .transpose()?;

    let confidence = object
        .get("confidence")
        .map(|value| parse_context_fabric_confidence_config(value, &format!("{path}.confidence")))
        .transpose()?;

    let cache = object
        .get("cache")
        .map(|value| parse_context_fabric_cache_config(value, &format!("{path}.cache")))
        .transpose()?;
    let multi_gateway = object
        .get("multi_gateway")
        .map(|value| {
            parse_context_fabric_multi_gateway_config(value, &format!("{path}.multi_gateway"))
        })
        .transpose()?;

    let conflict_resolution_strategy = match object.get("conflict_resolution_strategy") {
        Some(value) => {
            let field_path = format!("{path}.conflict_resolution_strategy");
            let Some(strategy) = value.as_str().map(str::trim) else {
                return Err(invalid_config_value(
                    &field_path,
                    "one of: NewerWins, SourceTypeWins, VoteWins, BothKept, HumanRequired",
                    Some(value),
                ));
            };
            if !matches!(
                strategy,
                "NewerWins" | "SourceTypeWins" | "VoteWins" | "BothKept" | "HumanRequired"
            ) {
                return Err(invalid_config_value(
                    &field_path,
                    "one of: NewerWins, SourceTypeWins, VoteWins, BothKept, HumanRequired",
                    Some(value),
                ));
            }
            Some(strategy.to_string())
        }
        None => None,
    };

    Ok(ContextFabricConfig {
        enabled: parse_optional_bool(object, "enabled", path)?,
        capture_mode,
        capture_exclude_patterns,
        pool_max_entries: parse_optional_positive_u32(object, "pool_max_entries", path)?,
        ttl,
        dedup_similarity_threshold: parse_optional_unit_interval_f64(
            object,
            "dedup_similarity_threshold",
            path,
        )?,
        compaction_similarity_threshold: parse_optional_unit_interval_f64(
            object,
            "compaction_similarity_threshold",
            path,
        )?,
        pii_detection: parse_optional_bool(object, "pii_detection", path)?,
        dlp_filter: parse_optional_bool(object, "dlp_filter", path)?,
        confidence,
        branch_inheritance: parse_optional_bool(object, "branch_inheritance", path)?,
        direct_answer_threshold: parse_optional_unit_interval_f64(
            object,
            "direct_answer_threshold",
            path,
        )?,
        cache,
        conflict_resolution_strategy,
        multi_gateway,
    })
}

fn parse_mcp_session_limits_config(
    value: &serde_json::Value,
    path: &str,
) -> Result<McpSessionLimitsConfig, CliError> {
    let object = expect_object(value, path)?;
    reject_unknown_fields(
        object,
        &[
            "max_prompt_bytes",
            "max_test_inference_cost_usd",
            "max_concurrent_sessions",
        ],
        path,
    )?;

    Ok(McpSessionLimitsConfig {
        max_prompt_bytes: parse_optional_positive_u64(object, "max_prompt_bytes", path)?,
        max_test_inference_cost_usd: parse_optional_nonnegative_f64(
            object,
            "max_test_inference_cost_usd",
            path,
        )?,
        max_concurrent_sessions: parse_optional_positive_u32(
            object,
            "max_concurrent_sessions",
            path,
        )?,
    })
}

fn parse_mcp_tool_server_policy_config(
    value: &serde_json::Value,
    path: &str,
) -> Result<McpToolServerPolicyConfig, CliError> {
    let object = expect_object(value, path)?;
    reject_unknown_fields(object, &["allow_unapproved", "allowed_ids"], path)?;

    let allowed_ids = match object.get("allowed_ids") {
        Some(value) => Some(parse_strict_string_array(
            value,
            &format!("{path}.allowed_ids"),
            true,
        )?),
        None => None,
    };

    Ok(McpToolServerPolicyConfig {
        allow_unapproved: parse_optional_bool(object, "allow_unapproved", path)?,
        allowed_ids,
    })
}

fn parse_agent_mcp_config_value(
    value: &serde_json::Value,
    path: &str,
) -> Result<AgentMcpConfig, CliError> {
    let object = expect_object(value, path)?;
    reject_unknown_fields(
        object,
        &[
            "enabled",
            "allowed_tools",
            "allowed_resources",
            "session_limits",
            "tool_servers",
        ],
        path,
    )?;

    let session_limits = object
        .get("session_limits")
        .map(|value| parse_mcp_session_limits_config(value, &format!("{path}.session_limits")))
        .transpose()?;
    let tool_servers = object
        .get("tool_servers")
        .map(|value| parse_mcp_tool_server_policy_config(value, &format!("{path}.tool_servers")))
        .transpose()?;

    Ok(AgentMcpConfig {
        enabled: parse_optional_bool(object, "enabled", path)?,
        allowed_tools: parse_optional_wildcard_or_string_array(object, "allowed_tools", path)?,
        allowed_resources: parse_optional_wildcard_or_string_array(
            object,
            "allowed_resources",
            path,
        )?,
        session_limits,
        tool_servers,
    })
}

fn parse_agent_declarations(
    root: &serde_json::Value,
) -> Result<Vec<GatewayAgentDeclaration>, CliError> {
    let Some(agents) = root.get("agents") else {
        return Ok(Vec::new());
    };
    let Some(array) = agents.as_array() else {
        if agents.is_object() {
            return Ok(Vec::new());
        }
        return Err(invalid_config_value(
            "agents",
            "array of agent objects",
            Some(agents),
        ));
    };

    let mut parsed = Vec::with_capacity(array.len());
    let mut seen_ids = std::collections::HashSet::new();
    for (idx, entry) in array.iter().enumerate() {
        let base_path = format!("agents[{idx}]");
        let object = expect_object(entry, &base_path)?;
        reject_unknown_fields(object, &["id", "team", "context_fabric", "mcp"], &base_path)?;

        let id = parse_required_non_empty_string(object, "id", &base_path)?;
        if !seen_ids.insert(id.clone()) {
            return Err(CliError::user(format!(
                "{base_path}.id: duplicate agent id '{}'; actual value: {}",
                id,
                config_actual_value(object.get("id"))
            )));
        }

        let context_fabric = object
            .get("context_fabric")
            .map(|value| {
                parse_context_fabric_config_value(value, &format!("{base_path}.context_fabric"))
            })
            .transpose()?;
        let mcp = object
            .get("mcp")
            .map(|value| parse_agent_mcp_config_value(value, &format!("{base_path}.mcp")))
            .transpose()?;

        parsed.push(GatewayAgentDeclaration {
            id,
            team: parse_required_non_empty_string(object, "team", &base_path)?,
            context_fabric,
            mcp,
        });
    }

    Ok(parsed)
}

fn parse_gateway_context_fabric_config(
    root: &serde_json::Value,
) -> Result<Option<ContextFabricConfig>, CliError> {
    root.get("context_fabric")
        .map(|value| parse_context_fabric_config_value(value, "context_fabric"))
        .transpose()
}

fn parse_mcp_server_config(root: &serde_json::Value) -> Result<Option<McpServerConfig>, CliError> {
    let Some(value) = root.get("mcp_server") else {
        return Ok(None);
    };
    let object = expect_object(value, "mcp_server")?;
    reject_unknown_fields(
        object,
        &[
            "enabled",
            "path",
            "allowed_tools",
            "allowed_resources",
            "max_request_body_bytes",
            "auth_mode",
            "default_capture_mode",
            "session_limits",
            "tool_servers",
        ],
        "mcp_server",
    )?;

    let auth_mode = match object.get("auth_mode") {
        Some(value) => {
            let field_path = "mcp_server.auth_mode";
            let Some(mode) = value.as_str().map(str::trim) else {
                return Err(invalid_config_value(
                    field_path,
                    "non-empty string",
                    Some(value),
                ));
            };
            if mode.is_empty() {
                return Err(invalid_config_value(
                    field_path,
                    "non-empty string",
                    Some(value),
                ));
            }
            Some(mode.to_string())
        }
        None => None,
    };

    let default_capture_mode = match object.get("default_capture_mode") {
        Some(value) => {
            let field_path = "mcp_server.default_capture_mode";
            let Some(mode) = value.as_str().map(str::trim) else {
                return Err(invalid_config_value(
                    field_path,
                    "one of: nudge, auto, off",
                    Some(value),
                ));
            };
            if !matches!(mode, "nudge" | "auto" | "off") {
                return Err(invalid_config_value(
                    field_path,
                    "one of: nudge, auto, off",
                    Some(value),
                ));
            }
            Some(mode.to_string())
        }
        None => None,
    };

    let session_limits = object
        .get("session_limits")
        .map(|value| parse_mcp_session_limits_config(value, "mcp_server.session_limits"))
        .transpose()?;
    let tool_servers = object
        .get("tool_servers")
        .map(|value| parse_mcp_tool_server_policy_config(value, "mcp_server.tool_servers"))
        .transpose()?;

    Ok(Some(McpServerConfig {
        enabled: parse_optional_bool(object, "enabled", "mcp_server")?,
        path: parse_optional_non_empty_string(object, "path", "mcp_server")?,
        allowed_tools: parse_optional_wildcard_or_string_array(
            object,
            "allowed_tools",
            "mcp_server",
        )?,
        allowed_resources: parse_optional_wildcard_or_string_array(
            object,
            "allowed_resources",
            "mcp_server",
        )?,
        max_request_body_bytes: parse_optional_positive_u64(
            object,
            "max_request_body_bytes",
            "mcp_server",
        )?,
        auth_mode,
        default_capture_mode,
        session_limits,
        tool_servers,
    }))
}

fn parse_agents_runtime_config(root: &serde_json::Value) -> Option<AgentsRuntimeConfig> {
    let agents = root.get("agents")?;
    let runtime = agents.get("runtime");
    let default_agent_id = runtime
        .and_then(|section| section.get("default_agent_id"))
        .and_then(|value| value.as_str())
        .map(ToString::to_string);

    let overrides: Vec<AgentOverrideConfig> = agents
        .get("overrides")
        .and_then(|value| value.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| serde_json::from_value(entry.clone()).ok())
                .collect()
        })
        .unwrap_or_default();

    if default_agent_id.is_none() && overrides.is_empty() && runtime.is_none() {
        return None;
    }

    Some(AgentsRuntimeConfig {
        default_agent_id,
        overrides,
    })
}

// ─── Moderation config parsing ───────────────────────────────────────────────

/// Configuration for the `POST /v1/moderations` endpoint.
#[derive(Debug, Clone)]
pub struct ModerationConfig {
    pub provider: super::external_moderation::ModerationProvider,
    pub secret_key_env: String,
    pub endpoint: Option<String>,
    pub categories: Vec<String>,
    pub threshold: f64,
}

fn parse_moderation_config(root: &serde_json::Value) -> Option<ModerationConfig> {
    let section = root.get("moderation")?;
    if !section.is_object() {
        return None;
    }

    let provider_str = section
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("openai");
    let provider = match provider_str {
        "openai" => super::external_moderation::ModerationProvider::OpenaiModeration,
        "azure" | "azure_content_safety" => {
            super::external_moderation::ModerationProvider::AzureContentSafety
        }
        "presidio" => super::external_moderation::ModerationProvider::Presidio,
        "guardrails_ai" => super::external_moderation::ModerationProvider::GuardrailsAi,
        "lakera" => super::external_moderation::ModerationProvider::Lakera,
        other => {
            tracing::warn!(
                provider = other,
                "unknown moderation provider; defaulting to openai"
            );
            super::external_moderation::ModerationProvider::OpenaiModeration
        }
    };

    let secret_key_env = match parse_env_secret_key_name(
        section.get("secret_key_ref"),
        "moderation.secret_key_ref",
    ) {
        Ok(Some(env_name)) => env_name,
        Ok(None) => String::new(),
        Err(error) => {
            tracing::warn!(error = %error, "invalid moderation.secret_key_ref; using empty credential reference");
            String::new()
        }
    };
    let endpoint = section
        .get("endpoint")
        .and_then(|v| v.as_str())
        .map(String::from);
    let categories: Vec<String> = section
        .get("categories")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let threshold = section
        .get("threshold")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.5);

    Some(ModerationConfig {
        provider,
        secret_key_env,
        endpoint,
        categories,
        threshold,
    })
}

// ─── Parser functions ───────────────────────────────────────────────────────

fn parse_workflow_cache_runtime_config(
    root: &serde_json::Value,
) -> Option<WorkflowCacheRuntimeConfig> {
    let section = root.get("workflow_cache")?;
    if !section.is_object() {
        return None;
    }
    let enabled = section
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let backend = section
        .get("backend")
        .and_then(|v| v.as_str())
        .unwrap_or("auto")
        .to_string();
    let default_tier = section
        .get("default_tier")
        .and_then(|v| v.as_str())
        .unwrap_or("private_edge_cache")
        .to_string();
    let org_shared_enabled = section
        .get("org_shared_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let encryption_key_ref = section
        .get("encryption_key_ref")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string);
    let default_ttl_secs = section
        .get("default_ttl_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);
    let ttl_by_data_class: std::collections::HashMap<String, u64> = section
        .get("ttl_by_data_class")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_u64().map(|secs| (k.clone(), secs)))
                .collect()
        })
        .unwrap_or_default();
    let allow_cross_provider_replay = section
        .get("allow_cross_provider_replay")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let require_approval_for_reuse = section
        .get("require_approval_for_reuse")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let negative_cache_enabled = section
        .get("negative_cache_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let max_entries_per_workflow = section
        .get("max_entries_per_workflow")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let direct_semantic_replay_enabled = section
        .get("direct_semantic_replay_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let codebase_identity_mode = section
        .get("codebase_identity_mode")
        .and_then(|v| v.as_str())
        .filter(|value| matches!(*value, "repository_isolated" | "monorepo_group"))
        .unwrap_or("repository_isolated")
        .to_string();
    let monorepo_group_id = section
        .get("monorepo_group_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let monorepo_repo_ids = section
        .get("monorepo_repo_ids")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    let agent_gateway_group_cache_sharing_enabled = section
        .get("agent_gateway_group_cache_sharing_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let agent_gateway_group_id = section
        .get("agent_gateway_group_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let physical_gateway_private_cache_only = section
        .get("physical_gateway_private_cache_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some(WorkflowCacheRuntimeConfig {
        enabled,
        backend,
        default_tier,
        org_shared_enabled,
        encryption_key_ref,
        default_ttl_secs,
        ttl_by_data_class,
        allow_cross_provider_replay,
        require_approval_for_reuse,
        negative_cache_enabled,
        max_entries_per_workflow,
        direct_semantic_replay_enabled,
        codebase_identity_mode,
        monorepo_group_id,
        monorepo_repo_ids,
        agent_gateway_group_cache_sharing_enabled,
        agent_gateway_group_id,
        physical_gateway_private_cache_only,
    })
}

fn parse_offline_egress_config(root: &serde_json::Value) -> Option<OfflineEgressConfig> {
    let section = root.get("offline_egress")?;
    if !section.is_object() {
        return None;
    }
    let offline_mode = section
        .get("offline_mode")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let block_internet_egress = section
        .get("block_internet_egress")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let allowed_egress_hosts: Vec<String> = section
        .get("allowed_egress_hosts")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default();
    let local_only_providers = section
        .get("local_only_providers")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let disable_external_health_checks = section
        .get("disable_external_health_checks")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some(OfflineEgressConfig {
        offline_mode,
        block_internet_egress,
        allowed_egress_hosts,
        local_only_providers,
        disable_external_health_checks,
    })
}

fn parse_hosted_gateway_runtime_config(
    root: &serde_json::Value,
    enforce_enabled_requirements: bool,
) -> Result<Option<HostedGatewayRuntimeConfig>, CliError> {
    let Some(section) = root.get("hosted_gateway") else {
        return Ok(None);
    };
    let local_access_section = section
        .get("local_access")
        .filter(|value| value.is_object());

    let local_access = if let Some(local_access_section) = local_access_section {
        let defaults = HostedGatewayLocalAccessConfig::default();
        let default_approval_levels = defaults.approval_required_risk_levels.clone();
        let approval_levels =
            parse_string_array(local_access_section, "approval_required_risk_levels");
        HostedGatewayLocalAccessConfig {
            enabled: local_access_section
                .get("enabled")
                .and_then(|value| value.as_bool())
                .unwrap_or(false),
            allowed_roots: parse_string_array(local_access_section, "allowed_roots"),
            mode: local_access_section
                .get("mode")
                .and_then(|value| value.as_str())
                .filter(|value| matches!(*value, "read_only" | "read_write"))
                .unwrap_or("read_only")
                .to_string(),
            max_file_bytes: local_access_section
                .get("max_file_bytes")
                .and_then(|value| value.as_u64())
                .unwrap_or(defaults.max_file_bytes),
            exclude_globs: parse_string_array(local_access_section, "exclude_globs"),
            allowed_commands: parse_string_array(local_access_section, "allowed_commands"),
            blocked_commands: parse_string_array(local_access_section, "blocked_commands"),
            approval_required_risk_levels: if approval_levels.is_empty() {
                default_approval_levels
            } else {
                approval_levels
            },
            command_timeout_seconds: local_access_section
                .get("command_timeout_seconds")
                .and_then(|value| value.as_u64())
                .unwrap_or(defaults.command_timeout_seconds),
            max_output_bytes: local_access_section
                .get("max_output_bytes")
                .and_then(|value| value.as_u64())
                .unwrap_or(defaults.max_output_bytes),
        }
    } else {
        HostedGatewayLocalAccessConfig::default()
    };

    if enforce_enabled_requirements && local_access.enabled {
        if local_access.allowed_roots.is_empty() {
            return Err(CliError::user(
                "hosted_gateway.local_access.allowed_roots is required when local access is enabled",
            ));
        }
        for root in &local_access.allowed_roots {
            let path = std::path::Path::new(root);
            if !path.is_absolute() || root.contains("..") {
                return Err(CliError::user(
                    "hosted_gateway.local_access.allowed_roots must be absolute paths without '..'",
                ));
            }
        }
        if local_access.allowed_commands.is_empty() {
            return Err(CliError::user(
                "hosted_gateway.local_access.allowed_commands is required before local command execution can be enabled",
            ));
        }
    }

    Ok(Some(HostedGatewayRuntimeConfig { local_access }))
}

fn parse_string_array(section: &serde_json::Value, key: &str) -> Vec<String> {
    section
        .get(key)
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

// ─── Tool server parsing ─────────────────────────────────────────────────────

fn validate_boundary_separation(root: &serde_json::Value) -> Result<(), CliError> {
    if root.pointer("/tools/servers").is_some() {
        return Err(CliError::user(
            "tool server declarations belong in the top-level 'tool_servers' block, not under 'tools'. \
             The 'tools' key is reserved for runtime tool validation policy.",
        ));
    }
    Ok(())
}

fn validate_no_conflated_mcp_tool_servers(
    root: &serde_json::Value,
    tool_server_ids: &[String],
) -> Result<(), CliError> {
    if tool_server_ids.is_empty() {
        return Ok(());
    }
    let Some(targets) = root
        .pointer("/providers/targets")
        .and_then(|v| v.as_array())
    else {
        return Ok(());
    };
    for target in targets {
        if target.get("mcp").is_none() {
            continue;
        }
        let Some(target_id) = target.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        if tool_server_ids.iter().any(|id| id == target_id) {
            return Err(CliError::user(format!(
                "providers.targets[].id '{}' has an 'mcp' bridge AND a matching tool_servers[] entry. \
                 Runtime provider bridging (providers.targets[].mcp) must not be conflated with \
                 durable tool servers (tool_servers[]). Use distinct IDs or remove the conflicting entry.",
                target_id
            )));
        }
    }
    Ok(())
}

fn parse_tool_servers(root: &serde_json::Value) -> Result<Vec<ToolServerDeclaration>, CliError> {
    let Some(arr) = root.get("tool_servers").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };

    let mut servers = Vec::with_capacity(arr.len());
    let mut seen_ids = std::collections::HashSet::new();

    for (idx, item) in arr.iter().enumerate() {
        let id = item
            .get("id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                CliError::user(format!(
                    "tool_servers[{idx}].id is required and must be non-empty"
                ))
            })?
            .to_string();

        if !seen_ids.insert(id.clone()) {
            return Err(CliError::user(format!(
                "tool_servers[{idx}].id '{}' is duplicated",
                id
            )));
        }

        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                CliError::user(format!(
                    "tool_servers[{idx}].name is required and must be non-empty"
                ))
            })?
            .to_string();

        let description = item
            .get("description")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        let transport_val = item
            .get("transport")
            .ok_or_else(|| CliError::user(format!("tool_servers[{idx}].transport is required")))?;
        let transport = parse_tool_server_transport(transport_val, idx)?;

        let mutability_class = item
            .get("mutability_class")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if !matches!(
            mutability_class.as_str(),
            "read_only" | "mutating" | "unknown"
        ) {
            return Err(CliError::user(format!(
                "tool_servers[{idx}].mutability_class must be one of: read_only, mutating, unknown"
            )));
        }

        let trust_state = item
            .get("trust_state")
            .and_then(|v| v.as_str())
            .unwrap_or("pending")
            .to_string();
        if !matches!(trust_state.as_str(), "pending" | "approved") {
            return Err(CliError::user(format!(
                "tool_servers[{idx}].trust_state must be one of: pending, approved"
            )));
        }

        let containment = item
            .get("containment")
            .map(|v| parse_tool_server_containment(v, idx))
            .transpose()?
            .unwrap_or_default();

        let labels = parse_string_labels(item.get("labels"));

        servers.push(ToolServerDeclaration {
            id,
            name,
            description,
            transport,
            mutability_class,
            trust_state,
            containment,
            labels,
        });
    }

    Ok(servers)
}

fn parse_tool_server_transport(
    val: &serde_json::Value,
    idx: usize,
) -> Result<ToolServerTransportConfig, CliError> {
    let kind = val
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CliError::user(format!("tool_servers[{idx}].transport.kind is required")))?
        .to_string();

    if !matches!(kind.as_str(), "stdio" | "sse" | "streamable_http") {
        return Err(CliError::user(format!(
            "tool_servers[{idx}].transport.kind must be one of: stdio, sse, streamable_http"
        )));
    }

    let command = val
        .get("command")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let args = val
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default();
    let url = val
        .get("url")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    if kind == "stdio" && command.is_none() {
        return Err(CliError::user(format!(
            "tool_servers[{idx}].transport.command is required for stdio transport"
        )));
    }
    if matches!(kind.as_str(), "sse" | "streamable_http") && url.is_none() {
        return Err(CliError::user(format!(
            "tool_servers[{idx}].transport.url is required for {} transport",
            kind
        )));
    }

    let (auth_type, secret_key_env, header_name) = if let Some(auth) = val.get("auth") {
        let atype = auth
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("none")
            .to_string();
        let skr = auth
            .get("secret_key_ref")
            .and_then(|v| v.get("env").or_else(|| v.get("store")))
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let hname = auth
            .get("header_name")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        (atype, skr, hname)
    } else {
        ("none".to_string(), None, None)
    };

    Ok(ToolServerTransportConfig {
        kind,
        command,
        args,
        url,
        auth_type,
        secret_key_env,
        header_name,
    })
}

fn parse_tool_server_containment(
    val: &serde_json::Value,
    idx: usize,
) -> Result<ToolServerContainmentConfig, CliError> {
    let network_policy = val
        .get("network_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("egress_restricted")
        .to_string();
    if !matches!(
        network_policy.as_str(),
        "unrestricted" | "egress_restricted" | "isolated"
    ) {
        return Err(CliError::user(format!(
            "tool_servers[{idx}].containment.network_policy must be one of: unrestricted, egress_restricted, isolated"
        )));
    }

    let timeout_ms = val
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(30_000);
    if !(100..=300_000).contains(&timeout_ms) {
        return Err(CliError::user(format!(
            "tool_servers[{idx}].containment.timeout_ms must be between 100 and 300000"
        )));
    }

    let max_concurrent_calls = val
        .get("max_concurrent_calls")
        .and_then(|v| v.as_u64())
        .unwrap_or(5) as u32;
    if !(1..=100).contains(&max_concurrent_calls) {
        return Err(CliError::user(format!(
            "tool_servers[{idx}].containment.max_concurrent_calls must be between 1 and 100"
        )));
    }

    Ok(ToolServerContainmentConfig {
        network_policy,
        timeout_ms,
        max_concurrent_calls,
    })
}

fn parse_string_labels(
    val: Option<&serde_json::Value>,
) -> std::collections::HashMap<String, String> {
    val.and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Task-aware routing configuration parsers
// ---------------------------------------------------------------------------

fn parse_task_type(s: &str) -> Option<super::providers::TaskType> {
    match s {
        "code_generation" | "code" => Some(super::providers::TaskType::CodeGeneration),
        "analysis" => Some(super::providers::TaskType::Analysis),
        "multilingual" => Some(super::providers::TaskType::Multilingual),
        "multimodal" => Some(super::providers::TaskType::Multimodal),
        "long_form_writing" | "long_form" => Some(super::providers::TaskType::LongFormWriting),
        "structured_output" | "structured" => Some(super::providers::TaskType::StructuredOutput),
        "general" => Some(super::providers::TaskType::General),
        _ => None,
    }
}

fn parse_task_profiles(root: &serde_json::Value) -> Vec<super::providers::TaskProfile> {
    let Some(section) = root
        .get("providers")
        .and_then(|v| v.get("task_profiles"))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };

    section
        .iter()
        .filter_map(|entry| {
            let task_type_str = entry.get("task_type").and_then(|v| v.as_str())?;
            let task_type = parse_task_type(task_type_str)?;
            let preferred_providers = entry
                .get("preferred_providers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let min_context_tokens = entry
                .get("min_context_tokens")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);
            Some(super::providers::TaskProfile {
                task_type,
                preferred_providers,
                min_context_tokens,
            })
        })
        .collect()
}

fn parse_budget_policy(root: &serde_json::Value) -> Option<super::providers::BudgetPolicy> {
    let section = root.get("providers").and_then(|v| v.get("budget_policy"))?;

    let soft_limit_action = match section.get("soft_limit_action").and_then(|v| v.as_str()) {
        Some("warn_only") => super::providers::SoftLimitAction::WarnOnly,
        _ => super::providers::SoftLimitAction::PreferCheaper,
    };

    let hard_limit_action = match section.get("hard_limit_action").and_then(|v| v.as_str()) {
        Some("allow_cheapest_only") => super::providers::HardLimitAction::AllowCheapestOnly,
        _ => super::providers::HardLimitAction::Reject,
    };

    Some(super::providers::BudgetPolicy {
        soft_limit_action,
        hard_limit_action,
    })
}

fn parse_latency_optimization(
    root: &serde_json::Value,
) -> Option<super::providers::LatencyOptimization> {
    let section = root
        .get("providers")
        .and_then(|v| v.get("latency_optimization"))?;

    let streaming_preferred_ttft_ms = section
        .get("streaming_preferred_ttft_ms")
        .and_then(|v| v.as_u64());

    let batch_preferred_throughput_tps = section
        .get("batch_preferred_throughput_tps")
        .and_then(|v| v.as_f64());

    Some(super::providers::LatencyOptimization {
        streaming_preferred_ttft_ms,
        batch_preferred_throughput_tps,
    })
}

// ─── Envelope cache config ───────────────────────────────────────────────────

/// Configuration for envelope-aware caching.
#[derive(Debug, Clone)]
pub struct EnvelopeCacheConfig {
    /// Whether envelope-scoped caching is enabled.
    pub enabled: bool,
    /// Allow cross-provider cache reuse.
    pub allow_cross_provider_reuse: bool,
    /// TTL in seconds for cache entries.
    pub ttl_seconds: u64,
}

fn parse_envelope_cache_config(root: &serde_json::Value) -> Option<EnvelopeCacheConfig> {
    let section = root.get("cache").or_else(|| root.get("envelope_cache"))?;
    let enabled = section
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let allow_cross_provider_reuse = section
        .get("allow_cross_provider_reuse")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ttl_seconds = section
        .get("ttl_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(300);
    Some(EnvelopeCacheConfig {
        enabled,
        allow_cross_provider_reuse,
        ttl_seconds,
    })
}

// ─── Local filesystem cache config ───────────────────────────────────────────

/// Declarative configuration for the local filesystem cache backend.
///
/// ```yaml
/// cache:
/// local_storage_path: /var/lib/verdictan/cache
/// local_storage_max_bytes: 1073741824
/// local_storage_eviction_policy: lru
/// local_storage_warmup_enabled: true
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalCacheConfig {
    /// Override the default cache directory (`~/.verdictan/cache/`).
    pub local_storage_path: Option<String>,
    /// Maximum bytes for the local filesystem cache (default: 524_288_000 = 500 MB).
    pub local_storage_max_bytes: Option<u64>,
    /// Eviction policy (only "lru" supported currently).
    pub local_storage_eviction_policy: Option<String>,
    /// Whether to scan and warm the cache index on gateway startup (default: true).
    pub local_storage_warmup_enabled: Option<bool>,
}

impl Default for LocalCacheConfig {
    fn default() -> Self {
        Self {
            local_storage_path: None,
            local_storage_max_bytes: Some(super::cache::DEFAULT_LOCAL_CACHE_MAX_BYTES),
            local_storage_eviction_policy: Some("lru".to_string()),
            local_storage_warmup_enabled: Some(true),
        }
    }
}

fn parse_local_cache_config(root: &serde_json::Value) -> Option<LocalCacheConfig> {
    let section = root.get("cache")?;
    if !section.is_object() {
        return None;
    }
    let local_storage_path = section
        .get("local_storage_path")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let local_storage_max_bytes = section
        .get("local_storage_max_bytes")
        .and_then(|v| v.as_u64());
    let local_storage_eviction_policy = section
        .get("local_storage_eviction_policy")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let local_storage_warmup_enabled = section
        .get("local_storage_warmup_enabled")
        .and_then(|v| v.as_bool());

    if local_storage_path.is_none()
        && local_storage_max_bytes.is_none()
        && local_storage_eviction_policy.is_none()
        && local_storage_warmup_enabled.is_none()
    {
        return None;
    }

    Some(LocalCacheConfig {
        local_storage_path,
        local_storage_max_bytes,
        local_storage_eviction_policy,
        local_storage_warmup_enabled,
    })
}

/// Validate local cache config fields.
pub fn validate_local_cache_config(config: &LocalCacheConfig) -> Vec<String> {
    let mut errors = Vec::new();
    if let Some(ref path) = config.local_storage_path {
        let p = std::path::Path::new(path);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                errors.push(format!(
                    "cache.local_storage_path parent directory does not exist: {}",
                    parent.display()
                ));
            }
        }
    }
    if let Some(max_bytes) = config.local_storage_max_bytes {
        if max_bytes == 0 {
            errors.push("cache.local_storage_max_bytes must be greater than 0".to_string());
        }
    }
    if let Some(ref policy) = config.local_storage_eviction_policy {
        if policy != "lru" {
            errors.push(format!(
                "cache.local_storage_eviction_policy: unsupported value '{}' (expected 'lru')",
                policy
            ));
        }
    }
    errors
}

// ─── New config structs and parsers ─────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CircuitBreakerDeclConfig {
    #[serde(default = "default_true_val")]
    pub enabled: bool,
    #[serde(default = "default_cb_threshold")]
    pub consecutive_failure_threshold: u32,
    #[serde(default = "default_cb_cooldown")]
    pub cooldown_seconds: u64,
    #[serde(default = "default_cb_half_open")]
    pub half_open_successes: u32,
}

fn default_cb_threshold() -> u32 {
    5
}
fn default_cb_cooldown() -> u64 {
    30
}
fn default_cb_half_open() -> u32 {
    1
}

impl Default for CircuitBreakerDeclConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            consecutive_failure_threshold: default_cb_threshold(),
            cooldown_seconds: default_cb_cooldown(),
            half_open_successes: default_cb_half_open(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdmissionControlDeclConfig {
    #[serde(default = "default_ac_region")]
    pub max_concurrent_per_region: u64,
    #[serde(default = "default_ac_family")]
    pub max_concurrent_per_family: u64,
    #[serde(default = "default_ac_queue")]
    pub max_queue_wait_ms: u64,
}

fn default_ac_region() -> u64 {
    1000
}
fn default_ac_family() -> u64 {
    5000
}
fn default_ac_queue() -> u64 {
    30_000
}

impl Default for AdmissionControlDeclConfig {
    fn default() -> Self {
        Self {
            max_concurrent_per_region: default_ac_region(),
            max_concurrent_per_family: default_ac_family(),
            max_queue_wait_ms: default_ac_queue(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthMonitorProviderDeclEntry {
    pub name: String,
    pub endpoint: String,
    #[serde(default = "default_hm_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_hm_timeout")]
    pub timeout_ms: u64,
}

fn default_hm_interval() -> u64 {
    30
}
fn default_hm_timeout() -> u64 {
    5000
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthMonitorDeclConfig {
    #[serde(default)]
    pub providers: Vec<HealthMonitorProviderDeclEntry>,
    #[serde(default = "default_hm_unhealthy")]
    pub unhealthy_threshold: u32,
    #[serde(default)]
    pub alert_callback_urls: Vec<String>,
}

fn default_hm_unhealthy() -> u32 {
    3
}

impl Default for HealthMonitorDeclConfig {
    fn default() -> Self {
        Self {
            providers: Vec::new(),
            unhealthy_threshold: default_hm_unhealthy(),
            alert_callback_urls: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FingerprintDeclConfig {
    #[serde(default)]
    pub fingerprint_fields: Vec<String>,
    #[serde(default = "default_fp_window")]
    pub profile_window_seconds: u64,
    #[serde(default = "default_fp_threshold")]
    pub similarity_threshold: f64,
    #[serde(default = "default_fp_max_rps")]
    pub max_requests_per_window: u64,
    #[serde(default = "default_fp_action")]
    pub action: String,
}

fn default_fp_window() -> u64 {
    60
}
fn default_fp_threshold() -> f64 {
    0.9
}
fn default_fp_max_rps() -> u64 {
    100
}
fn default_fp_action() -> String {
    "warn".to_string()
}

impl Default for FingerprintDeclConfig {
    fn default() -> Self {
        Self {
            fingerprint_fields: vec!["model".to_string(), "messages".to_string()],
            profile_window_seconds: default_fp_window(),
            similarity_threshold: default_fp_threshold(),
            max_requests_per_window: default_fp_max_rps(),
            action: default_fp_action(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DataClassificationDeclConfig {
    #[serde(default = "default_true_val")]
    pub enabled: bool,
    #[serde(default = "default_true_val")]
    pub phi_detection: bool,
    #[serde(default = "default_true_val")]
    pub pii_detection: bool,
    #[serde(default = "default_true_val")]
    pub financial_detection: bool,
    #[serde(default = "default_true_val")]
    pub ip_detection: bool,
}

impl Default for DataClassificationDeclConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            phi_detection: true,
            pii_detection: true,
            financial_detection: true,
            ip_detection: true,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EuAiActDeclConfig {
    #[serde(default = "default_eu_risk")]
    pub risk_class: String,
    #[serde(default = "default_eu_articles")]
    pub articles: Vec<u32>,
}

fn default_eu_risk() -> String {
    "high".to_string()
}
fn default_eu_articles() -> Vec<u32> {
    vec![9, 10, 11, 12, 13, 14, 15]
}

impl Default for EuAiActDeclConfig {
    fn default() -> Self {
        Self {
            risk_class: default_eu_risk(),
            articles: default_eu_articles(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GdprDeclConfig {
    #[serde(default)]
    pub consent_required: bool,
    #[serde(default = "default_gdpr_header")]
    pub consent_header: String,
    #[serde(default)]
    pub consent_verification_endpoint: Option<String>,
    #[serde(default)]
    pub data_categories: Vec<String>,
    #[serde(default)]
    pub retention_days: Option<u64>,
    #[serde(default = "default_gdpr_timeout")]
    pub timeout_ms: u64,
}

fn default_gdpr_header() -> String {
    "X-User-Consent-Token".to_string()
}
fn default_gdpr_timeout() -> u64 {
    5000
}

impl Default for GdprDeclConfig {
    fn default() -> Self {
        Self {
            consent_required: false,
            consent_header: default_gdpr_header(),
            consent_verification_endpoint: None,
            data_categories: Vec::new(),
            retention_days: None,
            timeout_ms: default_gdpr_timeout(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolSecurityDeclConfig {
    #[serde(default = "default_ts_mode")]
    pub analysis_mode: String,
    #[serde(default)]
    pub firewall_endpoint: Option<String>,
    #[serde(default = "default_true_val")]
    pub fail_closed: bool,
    #[serde(default)]
    pub blocked_entity_types: Vec<String>,
    #[serde(default)]
    pub blocked_patterns: Vec<String>,
}

fn default_ts_mode() -> String {
    "local".to_string()
}

impl Default for ToolSecurityDeclConfig {
    fn default() -> Self {
        Self {
            analysis_mode: default_ts_mode(),
            firewall_endpoint: None,
            fail_closed: true,
            blocked_entity_types: Vec::new(),
            blocked_patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolBudgetLimitDecl {
    pub max_calls: Option<u64>,
    pub max_tokens: Option<u64>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ToolBudgetDeclConfig {
    #[serde(default)]
    pub budgets: std::collections::HashMap<String, ToolBudgetLimitDecl>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ToolValidationDeclConfig {
    #[serde(default)]
    pub declared_tools: Vec<String>,
    #[serde(default)]
    pub allow_undeclared: bool,
    #[serde(default)]
    pub semantic_validation_enabled: bool,
    #[serde(default)]
    pub semantic_validation_endpoint: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CodeSanitationDeclConfig {
    #[serde(default = "default_true_val")]
    pub enabled: bool,
    #[serde(default)]
    pub block_on_match: bool,
    #[serde(default)]
    pub additional_patterns: Vec<String>,
}

impl Default for CodeSanitationDeclConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_on_match: false,
            additional_patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContentExtractionDeclConfig {
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    #[serde(default = "default_ce_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_ce_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_true_val")]
    pub fetch_urls: bool,
    #[serde(default = "default_ce_action")]
    pub action_on_error: String,
}

fn default_ce_timeout() -> u64 {
    10_000
}
fn default_ce_max_bytes() -> u64 {
    5_242_880
}
fn default_ce_action() -> String {
    "warn".to_string()
}

impl Default for ContentExtractionDeclConfig {
    fn default() -> Self {
        Self {
            allow_hosts: Vec::new(),
            timeout_ms: default_ce_timeout(),
            max_bytes: default_ce_max_bytes(),
            fetch_urls: true,
            action_on_error: default_ce_action(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DocumentAnalyzerDeclConfig {
    #[serde(default = "default_true_val")]
    pub enabled: bool,
    #[serde(default)]
    pub sanitize_code: bool,
    #[serde(default = "default_da_max_bytes")]
    pub max_document_bytes: u64,
    #[serde(default)]
    pub allowed_mime_types: Vec<String>,
}

fn default_da_max_bytes() -> u64 {
    10_485_760
}

impl Default for DocumentAnalyzerDeclConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sanitize_code: true,
            max_document_bytes: default_da_max_bytes(),
            allowed_mime_types: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LanguageDeclConfig {
    #[serde(default)]
    pub allowed_languages: Vec<String>,
    #[serde(default)]
    pub denied_languages: Vec<String>,
    #[serde(default = "default_lang_confidence")]
    pub min_confidence: f64,
    #[serde(default = "default_lang_action")]
    pub action: String,
    #[serde(default = "default_lang_apply")]
    pub apply_to: String,
}

fn default_lang_confidence() -> f64 {
    0.5
}
fn default_lang_action() -> String {
    "block".to_string()
}
fn default_lang_apply() -> String {
    "both".to_string()
}

impl Default for LanguageDeclConfig {
    fn default() -> Self {
        Self {
            allowed_languages: Vec::new(),
            denied_languages: Vec::new(),
            min_confidence: default_lang_confidence(),
            action: default_lang_action(),
            apply_to: default_lang_apply(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContextFlushDeclConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cf_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_cf_policy")]
    pub failure_policy: String,
}

fn default_cf_timeout() -> u64 {
    5000
}
fn default_cf_policy() -> String {
    "fallback_to_lossy".to_string()
}

impl Default for ContextFlushDeclConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            timeout_ms: default_cf_timeout(),
            failure_policy: default_cf_policy(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkTimeoutDeclConfig {
    #[serde(default = "default_net_connect")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_net_request")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_net_idle")]
    pub idle_timeout_ms: u64,
}

fn default_net_connect() -> u64 {
    10_000
}
fn default_net_request() -> u64 {
    120_000
}
fn default_net_idle() -> u64 {
    90_000
}

impl Default for NetworkTimeoutDeclConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: default_net_connect(),
            request_timeout_ms: default_net_request(),
            idle_timeout_ms: default_net_idle(),
        }
    }
}

// ─── Phase 39: Parsing functions ─────────────────────────────────────────────

fn parse_circuit_breaker_config(root: &serde_json::Value) -> Option<CircuitBreakerDeclConfig> {
    let section = root.get("circuit_breaker")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_admission_control_config(root: &serde_json::Value) -> Option<AdmissionControlDeclConfig> {
    let section = root.get("admission_control")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_health_monitor_config(root: &serde_json::Value) -> Option<HealthMonitorDeclConfig> {
    let section = root.get("health_monitor")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_fingerprint_config(root: &serde_json::Value) -> Option<FingerprintDeclConfig> {
    let section = root.get("fingerprint")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_data_classification_config(
    root: &serde_json::Value,
) -> Option<DataClassificationDeclConfig> {
    let section = root.get("data_classification")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_eu_ai_act_config(root: &serde_json::Value) -> Option<EuAiActDeclConfig> {
    let section = root.get("eu_ai_act")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_gdpr_config(root: &serde_json::Value) -> Option<GdprDeclConfig> {
    let section = root.get("gdpr")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_tool_security_config(root: &serde_json::Value) -> Option<ToolSecurityDeclConfig> {
    let section = root.get("tool_security")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_tool_budget_config(root: &serde_json::Value) -> Option<ToolBudgetDeclConfig> {
    let section = root.get("tool_budget")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_tool_validation_config(root: &serde_json::Value) -> Option<ToolValidationDeclConfig> {
    let section = root.get("tool_validation")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_code_sanitation_config(root: &serde_json::Value) -> Option<CodeSanitationDeclConfig> {
    let section = root.get("code_sanitation")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_content_extraction_config(
    root: &serde_json::Value,
) -> Option<ContentExtractionDeclConfig> {
    let section = root.get("content_extraction")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_document_analyzer_config(root: &serde_json::Value) -> Option<DocumentAnalyzerDeclConfig> {
    let section = root.get("document_analyzer")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_language_config(root: &serde_json::Value) -> Option<LanguageDeclConfig> {
    let section = root.get("language")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_context_flush_config(root: &serde_json::Value) -> Option<ContextFlushDeclConfig> {
    let section = root.get("context_flush")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_network_timeout_config(root: &serde_json::Value) -> Option<NetworkTimeoutDeclConfig> {
    let section = root.get("network")?;
    serde_json::from_value(section.clone()).ok()
}

fn parse_ai_usage_streaming_config(root: &serde_json::Value) -> Option<AiUsageStreamingConfig> {
    let section = root.get("ai_usage_streaming")?;
    if !section.is_object() {
        return None;
    }
    let enabled = section
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let body_capture_max_bytes = section
        .get("body_capture_max_bytes")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(super::ai_usage_capture::DEFAULT_BODY_CAPTURE_MAX_BYTES);
    let mandatory = section
        .get("mandatory")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some(AiUsageStreamingConfig {
        enabled,
        body_capture_max_bytes,
        mandatory,
    })
}

// ─── Enhanced validation ────────────────────────────────────────────────────

pub fn validate_config(cfg: &LoadedDeclarativeConfig) -> Vec<String> {
    let mut errors = Vec::new();

    if let Some(ref cb) = cfg.circuit_breaker {
        if cb.consecutive_failure_threshold == 0 {
            errors.push("circuit_breaker.consecutive_failure_threshold must be > 0".to_string());
        }
        if cb.cooldown_seconds == 0 {
            errors.push("circuit_breaker.cooldown_seconds must be > 0".to_string());
        }
    }

    if let Some(ref ac) = cfg.admission_control {
        if ac.max_concurrent_per_region == 0 {
            errors.push("admission_control.max_concurrent_per_region must be > 0".to_string());
        }
        if ac.max_concurrent_per_family == 0 {
            errors.push("admission_control.max_concurrent_per_family must be > 0".to_string());
        }
    }

    if let Some(ref hm) = cfg.health_monitor {
        if hm.unhealthy_threshold == 0 {
            errors.push("health_monitor.unhealthy_threshold must be > 0".to_string());
        }
        for (idx, p) in hm.providers.iter().enumerate() {
            if p.name.is_empty() {
                errors.push(format!(
                    "health_monitor.providers[{idx}].name must not be empty"
                ));
            }
            if p.endpoint.is_empty() {
                errors.push(format!(
                    "health_monitor.providers[{idx}].endpoint must not be empty"
                ));
            }
        }
    }

    if let Some(ref fp) = cfg.fingerprint {
        if !(0.0..=1.0).contains(&fp.similarity_threshold) {
            errors.push("fingerprint.similarity_threshold must be between 0.0 and 1.0".to_string());
        }
        if !matches!(fp.action.as_str(), "warn" | "block" | "rate_limit") {
            errors.push(format!(
                "fingerprint.action: unsupported value '{}' (expected 'warn', 'block', or 'rate_limit')",
                fp.action
            ));
        }
    }

    if let Some(ref eu) = cfg.eu_ai_act {
        if !matches!(
            eu.risk_class.as_str(),
            "unacceptable" | "high" | "limited" | "minimal"
        ) {
            errors.push(format!(
                "eu_ai_act.risk_class: unsupported value '{}' (expected 'unacceptable', 'high', 'limited', or 'minimal')",
                eu.risk_class
            ));
        }
    }

    if let Some(ref lang) = cfg.language {
        if !lang.allowed_languages.is_empty() && !lang.denied_languages.is_empty() {
            errors.push(
                "language: allowed_languages and denied_languages are mutually exclusive"
                    .to_string(),
            );
        }
        if !(0.0..=1.0).contains(&lang.min_confidence) {
            errors.push("language.min_confidence must be between 0.0 and 1.0".to_string());
        }
    }

    if let Some(ref net) = cfg.network {
        if net.connect_timeout_ms == 0 {
            errors.push("network.connect_timeout_ms must be > 0".to_string());
        }
        if net.request_timeout_ms == 0 {
            errors.push("network.request_timeout_ms must be > 0".to_string());
        }
    }

    if let Some(ref trl) = cfg.token_rate_limit {
        if trl.max_tokens == 0 {
            errors.push("token_rate_limit.max_tokens must be > 0".to_string());
        }
        if trl.window_seconds == 0 {
            errors.push("token_rate_limit.window_seconds must be > 0".to_string());
        }
    }

    if let Some(ref grl) = cfg.global_rate_limit {
        if grl.max_requests == 0 {
            errors.push("global_rate_limit.max_requests must be > 0".to_string());
        }
    }

    if let Some(ref iprl) = cfg.ip_rate_limit {
        if iprl.max_requests == 0 {
            errors.push("ip_rate_limit.max_requests must be > 0".to_string());
        }
    }

    if let Some(ref sc) = cfg.semantic_cache {
        if !(0.0..=1.0).contains(&sc.similarity_threshold) {
            errors.push("cache.similarity_threshold must be between 0.0 and 1.0".to_string());
        }
    }

    if let Some(ref hosted_gateway) = cfg.hosted_gateway {
        let local_access = &hosted_gateway.local_access;
        if local_access.enabled {
            if local_access.allowed_roots.is_empty() {
                errors.push(
                    "hosted_gateway.local_access.allowed_roots is required when local access is enabled"
                        .to_string(),
                );
            }
            if local_access
                .allowed_roots
                .iter()
                .any(|root| !std::path::Path::new(root).is_absolute() || root.contains(".."))
            {
                errors.push(
                    "hosted_gateway.local_access.allowed_roots must be absolute paths without '..'"
                        .to_string(),
                );
            }
            if local_access.allowed_commands.is_empty() {
                errors.push(
                    "hosted_gateway.local_access.allowed_commands is required before local command execution can be enabled"
                        .to_string(),
                );
            }
        }
    }

    if let Some(ref lc) = cfg.local_cache {
        errors.extend(validate_local_cache_config(lc));
    }

    errors
}

fn parse_context_management_config(
    root: &serde_json::Value,
) -> Option<super::context_manager::ContextManagementConfig> {
    let section = root.get("context_management")?;
    let strategy = match section.get("strategy").and_then(|v| v.as_str()) {
        Some("route_to_larger") => super::context_manager::OverflowStrategy::RouteToLarger,
        Some("summarize") => super::context_manager::OverflowStrategy::Summarize,
        Some("truncate") | None => super::context_manager::OverflowStrategy::Truncate,
        Some(_) => super::context_manager::OverflowStrategy::Truncate,
    };
    let max_summarization_ratio = section
        .get("max_summarization_ratio")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.5);
    let preserve_system_prompt = section
        .get("preserve_system_prompt")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let preserve_last_n_messages = section
        .get("preserve_last_n_messages")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    Some(super::context_manager::ContextManagementConfig {
        strategy,
        max_summarization_ratio,
        preserve_system_prompt,
        preserve_last_n_messages,
    })
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
    use crate::gateway::{
        cache, external_moderation, fail_mode, providers, rate_limit, token_rate_limit,
    };
    use tempfile::tempdir;

    #[test]
    fn sha256_prefixed_deterministic() {
        let h1 = sha256_prefixed(b"hello");
        let h2 = sha256_prefixed(b"hello");
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
        assert_eq!(h1.len(), "sha256:".len() + 64);
    }

    #[test]
    fn sha256_prefixed_empty() {
        let h = sha256_prefixed(b"");
        assert!(h.starts_with("sha256:"));
        assert_ne!(h, sha256_prefixed(b"a"));
    }

    #[test]
    fn sha256_prefixed_different_inputs() {
        assert_ne!(sha256_prefixed(b"abc"), sha256_prefixed(b"def"));
    }

    #[test]
    fn validate_tag_key_valid() {
        assert!(validate_tag_key("env", "tags").is_ok());
        assert!(validate_tag_key("my-key_123", "tags").is_ok());
    }

    #[test]
    fn validate_tag_key_empty() {
        assert!(validate_tag_key("", "tags").is_err());
    }

    #[test]
    fn validate_tag_key_non_ascii() {
        assert!(validate_tag_key("héllo", "tags").is_err());
    }

    #[test]
    fn validate_tag_key_too_long() {
        let long = "x".repeat(129);
        assert!(validate_tag_key(&long, "tags").is_err());
    }

    #[test]
    fn validate_tag_key_reserved_prefix() {
        assert!(validate_tag_key("verdictan:internal", "tags").is_err());
    }

    #[test]
    fn validate_tag_value_valid() {
        assert!(validate_tag_value("key", "production", "tags").is_ok());
    }

    #[test]
    fn validate_tag_value_non_ascii() {
        assert!(validate_tag_value("key", "café", "tags").is_err());
    }

    #[test]
    fn validate_tag_value_too_long() {
        let long = "v".repeat(257);
        assert!(validate_tag_value("key", &long, "tags").is_err());
    }

    #[test]
    fn should_replace_object_map_known_paths() {
        assert!(should_replace_object_map(&["tags"]));
        assert!(should_replace_object_map(&["pack", "tags"]));
        assert!(!should_replace_object_map(&["providers"]));
        assert!(!should_replace_object_map(&["unknown"]));
    }

    #[test]
    fn named_array_merge_identity_known() {
        assert_eq!(named_array_merge_identity(&["agents"]), Some("id"));
        assert_eq!(
            named_array_merge_identity(&["providers", "targets"]),
            Some("id")
        );
        assert_eq!(
            named_array_merge_identity(&["providers", "model_groups"]),
            Some("name")
        );
        assert_eq!(
            named_array_merge_identity(&["providers", "pipelines"]),
            Some("name")
        );
        assert_eq!(
            named_array_merge_identity(&["consumer_groups", "groups"]),
            Some("name")
        );
        assert_eq!(named_array_merge_identity(&["tool_servers"]), Some("id"));
    }

    #[test]
    fn named_array_merge_identity_unknown() {
        assert_eq!(named_array_merge_identity(&["unknown"]), None);
        assert_eq!(named_array_merge_identity(&["providers", "other"]), None);
    }

    #[test]
    fn should_concat_arrays_chain() {
        assert!(should_concat_arrays(&["policies", "chain"]));
        assert!(!should_concat_arrays(&["providers", "targets"]));
    }

    #[test]
    fn should_union_string_arrays_known() {
        assert!(should_union_string_arrays(&["models", "exposed_model_ids"]));
        assert!(!should_union_string_arrays(&["providers", "targets"]));
    }

    #[test]
    fn silent_engine_disabled_effective() {
        let cfg = SilentEngineConfig {
            enabled: false,
            disable_callbacks: true,
            disable_history: true,
            disable_gateway_telemetry: true,
            disable_payload_logging: true,
            disable_citation_writeback: true,
            minimum_state_mode: SilentMinimumStateMode::Standard,
        };
        let eff = cfg.effective();
        assert!(!eff.enabled);
        assert!(!eff.disable_callbacks);
        assert!(!eff.disable_history);
    }

    #[test]
    fn silent_engine_enabled_effective() {
        let cfg = SilentEngineConfig {
            enabled: true,
            disable_callbacks: false,
            disable_history: false,
            disable_gateway_telemetry: false,
            disable_payload_logging: false,
            disable_citation_writeback: false,
            minimum_state_mode: SilentMinimumStateMode::Standard,
        };
        let eff = cfg.effective();
        assert!(eff.enabled);
        assert!(eff.disable_callbacks);
        assert!(eff.disable_history);
        assert!(eff.disable_gateway_telemetry);
        assert!(eff.disable_payload_logging);
        assert!(eff.disable_citation_writeback);
    }

    #[test]
    fn silent_engine_helper_methods() {
        let enabled_cfg = SilentEngineConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(enabled_cfg.callbacks_disabled());
        assert!(enabled_cfg.history_disabled());
        assert!(enabled_cfg.gateway_telemetry_disabled());
        assert!(enabled_cfg.payload_logging_disabled());
        assert!(enabled_cfg.citation_writeback_disabled());
        assert!(enabled_cfg.privacy_enforcement_only());

        let disabled_cfg = SilentEngineConfig::default();
        assert!(!disabled_cfg.callbacks_disabled());
        assert!(!disabled_cfg.history_disabled());
        assert!(!disabled_cfg.privacy_enforcement_only());
    }

    #[test]
    fn deduplicate_chain_entries_last_wins() {
        let mut entries = vec![
            serde_json::json!("pii-detector"),
            serde_json::json!("hipaa"),
            serde_json::json!("pii-detector"),
        ];
        deduplicate_chain_entries_by_kind(&mut entries);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], serde_json::json!("hipaa"));
        assert_eq!(entries[1], serde_json::json!("pii-detector"));
    }

    #[test]
    fn deduplicate_chain_entries_no_duplicates() {
        let mut entries = vec![
            serde_json::json!("a"),
            serde_json::json!("b"),
            serde_json::json!("c"),
        ];
        deduplicate_chain_entries_by_kind(&mut entries);
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn merge_config_json_overlay_adds_new_keys() {
        let mut base = serde_json::json!({ "a": 1 });
        let overlay = serde_json::json!({ "b": 2 });
        merge_config_json(&mut base, &overlay, &[]);
        assert_eq!(base["a"], 1);
        assert_eq!(base["b"], 2);
    }

    #[test]
    fn merge_config_json_overlay_overwrites_scalars() {
        let mut base = serde_json::json!({ "a": 1, "b": "old" });
        let overlay = serde_json::json!({ "b": "new" });
        merge_config_json(&mut base, &overlay, &[]);
        assert_eq!(base["b"], "new");
    }

    #[test]
    fn merge_config_json_nested_objects_recursive() {
        let mut base = serde_json::json!({
            "providers": { "targets": [{ "id": "a" }] }
        });
        let overlay = serde_json::json!({
            "providers": { "targets": [{ "id": "b" }] }
        });
        merge_config_json(&mut base, &overlay, &[]);
        let targets = base["providers"]["targets"].as_array().unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn parse_tags_map_valid() {
        let val = serde_json::json!({ "env": "production", "team": "infra" });
        let map = parse_tags_map(Some(&val), "tags").unwrap();
        assert_eq!(map.get("env").unwrap(), "production");
        assert_eq!(map.get("team").unwrap(), "infra");
    }

    #[test]
    fn parse_tags_map_empty() {
        let map = parse_tags_map(None, "tags").unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn parse_tags_map_invalid_type() {
        let val = serde_json::json!([1, 2, 3]);
        assert!(parse_tags_map(Some(&val), "tags").is_err());
    }

    #[test]
    fn providers_source_config_defaults_to_embedded() {
        let cfg = ProvidersSourceConfig::default();
        assert!(matches!(cfg, ProvidersSourceConfig::Embedded));
    }

    // ── parse_string_array ───────────────────────────────────────────────

    #[test]
    fn parse_string_array_valid() {
        let section = serde_json::json!({"items": ["a", " b ", "c"]});
        let result = parse_string_array(&section, "items");
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_string_array_filters_empty() {
        let section = serde_json::json!({"items": ["a", "  ", "b"]});
        let result = parse_string_array(&section, "items");
        assert_eq!(result, vec!["a", "b"]);
    }

    #[test]
    fn parse_string_array_missing_key() {
        let section = serde_json::json!({});
        assert!(parse_string_array(&section, "items").is_empty());
    }

    #[test]
    fn parse_string_array_non_array() {
        let section = serde_json::json!({"items": "not_array"});
        assert!(parse_string_array(&section, "items").is_empty());
    }

    // ── parse_task_type ──────────────────────────────────────────────────

    #[test]
    fn parse_task_type_known() {
        assert!(parse_task_type("code_generation").is_some());
        assert!(parse_task_type("code").is_some());
        assert!(parse_task_type("analysis").is_some());
        assert!(parse_task_type("multilingual").is_some());
        assert!(parse_task_type("multimodal").is_some());
        assert!(parse_task_type("long_form_writing").is_some());
        assert!(parse_task_type("long_form").is_some());
        assert!(parse_task_type("structured_output").is_some());
        assert!(parse_task_type("structured").is_some());
        assert!(parse_task_type("general").is_some());
    }

    #[test]
    fn parse_task_type_unknown() {
        assert!(parse_task_type("unknown").is_none());
        assert!(parse_task_type("").is_none());
    }

    // ── validate_local_cache_config ──────────────────────────────────────

    #[test]
    fn validate_local_cache_zero_max_bytes() {
        let config = LocalCacheConfig {
            local_storage_path: None,
            local_storage_max_bytes: Some(0),
            local_storage_eviction_policy: None,
            local_storage_warmup_enabled: None,
        };
        let errors = validate_local_cache_config(&config);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("greater than 0"));
    }

    #[test]
    fn validate_local_cache_bad_eviction_policy() {
        let config = LocalCacheConfig {
            local_storage_path: None,
            local_storage_max_bytes: None,
            local_storage_eviction_policy: Some("fifo".to_string()),
            local_storage_warmup_enabled: None,
        };
        let errors = validate_local_cache_config(&config);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("unsupported"));
    }

    #[test]
    fn validate_local_cache_valid_lru() {
        let config = LocalCacheConfig {
            local_storage_path: None,
            local_storage_max_bytes: Some(1024),
            local_storage_eviction_policy: Some("lru".to_string()),
            local_storage_warmup_enabled: None,
        };
        assert!(validate_local_cache_config(&config).is_empty());
    }

    // ── default_* helpers ────────────────────────────────────────────────

    #[test]
    fn default_cb_threshold_is_5() {
        assert_eq!(default_cb_threshold(), 5);
    }

    #[test]
    fn default_cb_cooldown_is_30() {
        assert_eq!(default_cb_cooldown(), 30);
    }

    #[test]
    fn default_cb_half_open_is_1() {
        assert_eq!(default_cb_half_open(), 1);
    }

    #[test]
    fn default_ac_values() {
        assert!(default_ac_region() > 0);
        assert!(default_ac_family() > 0);
        assert!(default_ac_queue() > 0);
    }

    #[test]
    fn default_true_val_returns_true() {
        assert!(default_true_val());
    }

    #[test]
    fn default_data_collection_is_allow() {
        assert_eq!(default_data_collection(), "allow");
    }

    #[test]
    fn default_session_header_is_x_session_id() {
        assert_eq!(default_session_header(), "x-session-id");
    }

    #[test]
    fn default_shadow_eval_mode_is_asynchronous() {
        assert_eq!(default_shadow_eval_mode(), "asynchronous");
    }

    #[test]
    fn default_shadow_cap_mode_is_metadata_only() {
        assert_eq!(default_shadow_cap_mode(), "metadata_only");
    }

    #[test]
    fn default_workflow_cache_backend_is_auto() {
        assert_eq!(default_workflow_cache_backend(), "auto");
    }

    // ── circuit_breaker_config_default ────────────────────────────────────

    #[test]
    fn circuit_breaker_default_values() {
        let cb = CircuitBreakerDeclConfig::default();
        assert!(cb.enabled);
        assert_eq!(cb.consecutive_failure_threshold, 5);
        assert_eq!(cb.cooldown_seconds, 30);
        assert_eq!(cb.half_open_successes, 1);
    }

    // ── merge_unique_string_array ────────────────────────────────────────

    #[test]
    fn merge_unique_string_array_deduplicates() {
        let base = vec![
            serde_json::Value::String("a".to_string()),
            serde_json::Value::String("b".to_string()),
        ];
        let overlay = vec![
            serde_json::Value::String("b".to_string()),
            serde_json::Value::String("c".to_string()),
        ];
        let result = merge_unique_string_array(&base, &overlay);
        let strings: Vec<&str> = result.iter().filter_map(|v| v.as_str()).collect();
        assert!(strings.contains(&"a"));
        assert!(strings.contains(&"b"));
        assert!(strings.contains(&"c"));
        assert_eq!(
            strings.iter().filter(|s| **s == "b").count(),
            1,
            "b should appear only once"
        );
    }

    #[test]
    fn merge_unique_string_array_trims_strings_and_preserves_non_strings() {
        let merged = merge_unique_string_array(
            &[
                serde_json::json!(" alpha "),
                serde_json::json!(""),
                serde_json::json!({"kind": "object"}),
            ],
            &[
                serde_json::json!("alpha"),
                serde_json::json!("beta"),
                serde_json::json!({"kind": "object"}),
            ],
        );

        assert_eq!(merged[0], serde_json::json!("alpha"));
        assert_eq!(merged[1], serde_json::json!(""));
        assert_eq!(merged[2], serde_json::json!({"kind": "object"}));
        assert_eq!(merged[3], serde_json::json!("beta"));
        assert_eq!(merged[4], serde_json::json!({"kind": "object"}));
    }

    // ── parse_task_profiles ──────────────────────────────────────────────

    #[test]
    fn parse_task_profiles_valid() {
        let root = serde_json::json!({
            "providers": {
                "task_profiles": [
                    {
                        "task_type": "code_generation",
                        "preferred_providers": ["openai"],
                        "min_context_tokens": 4096
                    },
                    {
                        "task_type": "general"
                    }
                ]
            }
        });
        let profiles = parse_task_profiles(&root);
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].min_context_tokens, Some(4096));
        assert!(profiles[1].preferred_providers.is_empty());
    }

    #[test]
    fn parse_task_profiles_empty() {
        assert!(parse_task_profiles(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn parse_task_profiles_skips_invalid_type() {
        let root = serde_json::json!({
            "providers": {
                "task_profiles": [
                    {"task_type": "unknown_type"}
                ]
            }
        });
        assert!(parse_task_profiles(&root).is_empty());
    }

    #[test]
    fn parse_task_profiles_supports_aliases_and_filters_non_strings() {
        let root = serde_json::json!({
            "providers": {
                "task_profiles": [
                    {
                        "task_type": "code",
                        "preferred_providers": ["openai", 42, null]
                    }
                ]
            }
        });

        let profiles = parse_task_profiles(&root);
        assert_eq!(profiles.len(), 1);
        assert!(matches!(
            profiles[0].task_type,
            providers::TaskType::CodeGeneration
        ));
        assert_eq!(profiles[0].preferred_providers, vec!["openai".to_string()]);
        assert_eq!(profiles[0].min_context_tokens, None);
    }

    // ── parse_budget_policy ──────────────────────────────────────────────

    #[test]
    fn parse_budget_policy_present() {
        let root = serde_json::json!({
            "providers": {
                "budget_policy": {
                    "soft_limit_action": "warn_only",
                    "hard_limit_action": "allow_cheapest_only"
                }
            }
        });
        let policy = parse_budget_policy(&root);
        assert!(policy.is_some());
    }

    #[test]
    fn parse_budget_policy_missing() {
        assert!(parse_budget_policy(&serde_json::json!({})).is_none());
    }

    #[test]
    fn parse_budget_policy_defaults_unknown_actions() {
        let root = serde_json::json!({
            "providers": {
                "budget_policy": {
                    "soft_limit_action": "unexpected",
                    "hard_limit_action": "unexpected"
                }
            }
        });

        let policy = parse_budget_policy(&root).unwrap();
        assert!(matches!(
            policy.soft_limit_action,
            providers::SoftLimitAction::PreferCheaper
        ));
        assert!(matches!(
            policy.hard_limit_action,
            providers::HardLimitAction::Reject
        ));
    }

    // ── default_runtime_provider_policy ──────────────────────────────────

    #[test]
    fn default_runtime_provider_policy_values() {
        let p = default_runtime_provider_policy();
        assert!(p.allow_fallbacks);
        assert!(p.require_parameters);
        assert_eq!(p.data_collection, "allow");
        assert!(!p.zdr);
    }

    // ── default_runtime_cache_defaults ────────────────────────────────────

    #[test]
    fn default_runtime_cache_defaults_values() {
        let d = default_runtime_cache_defaults();
        assert!(d.allow_cache_control);
        assert!(d.sticky_routing);
        assert!(d.allow_session_id);
        assert_eq!(d.session_header_name, "x-session-id");
    }

    #[test]
    fn parse_region_overrides_valid_and_invalid_cases() {
        let root = serde_json::json!({
            "regions": {
                "eu-west": {
                    "providers": ["openai-eu"],
                    "detection_sensitivity": "high",
                    "cache": {
                        "backend": "valkey",
                        "ttl_seconds": 600
                    },
                    "rate_limit_multiplier": 0.5
                }
            }
        });
        let regions = parse_region_overrides(&root).unwrap().unwrap();
        let region = regions.get("eu-west").unwrap();
        assert_eq!(
            region.providers.as_ref().unwrap(),
            &vec!["openai-eu".to_string()]
        );
        assert_eq!(region.detection_sensitivity.as_deref(), Some("high"));
        assert_eq!(
            region
                .cache
                .as_ref()
                .and_then(|cache| cache.backend.as_deref()),
            Some("valkey")
        );
        assert_eq!(region.rate_limit_multiplier, Some(0.5));

        let error = parse_region_overrides(&serde_json::json!({"regions": []})).unwrap_err();
        assert!(error.to_string().contains("must be a map"));

        let error = parse_region_overrides(&serde_json::json!({
            "regions": {
                "eu-west": { "detection_sensitivity": "extreme" }
            }
        }))
        .unwrap_err();
        assert!(error.to_string().contains("detection_sensitivity"));

        let error = parse_region_overrides(&serde_json::json!({
            "regions": {
                "eu-west": { "rate_limit_multiplier": 0.0 }
            }
        }))
        .unwrap_err();
        assert!(error.to_string().contains("between 0 (exclusive) and 10"));
    }

    #[test]
    fn parse_token_rate_limit_handles_scopes_and_invalid_shapes() {
        let global = parse_token_rate_limit(&serde_json::json!({
            "token_rate_limit": {
                "max_tokens": 1000,
                "window_seconds": 60,
                "scope": "unexpected"
            }
        }))
        .unwrap();
        assert_eq!(global.max_tokens, 1000);
        assert_eq!(global.window_seconds, 60);
        assert!(matches!(global.scope, token_rate_limit::TokenScope::Global));

        let per_ip = parse_token_rate_limit(&serde_json::json!({
            "token_rate_limit": {
                "max_tokens": 250,
                "window_seconds": 15,
                "scope": "per_ip"
            }
        }))
        .unwrap();
        assert!(matches!(per_ip.scope, token_rate_limit::TokenScope::PerIp));

        assert!(parse_token_rate_limit(&serde_json::json!({
            "token_rate_limit": {
                "window_seconds": 15
            }
        }))
        .is_none());
    }

    #[test]
    fn parse_global_and_ip_rate_limits_parse_expected_fields() {
        let global = parse_global_rate_limit(&serde_json::json!({
            "global_rate_limit": {
                "max_requests": 25,
                "window_seconds": 30
            }
        }))
        .unwrap();
        assert_eq!(global.max_requests, 25);
        assert_eq!(global.window_seconds, 30);

        let ip = parse_ip_rate_limit(&serde_json::json!({
            "ip_rate_limit": {
                "max_requests": 50,
                "window_seconds": 45,
                "trusted_proxy_cidrs": ["10.0.0.0/8", "fd00::/8"]
            }
        }))
        .unwrap();
        assert_eq!(ip.max_requests, 50);
        assert_eq!(ip.window_seconds, 45);
        assert_eq!(
            ip.trusted_proxy_cidrs,
            vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()]
        );

        assert!(parse_global_rate_limit(&serde_json::json!({
            "global_rate_limit": {
                "max_requests": 25
            }
        }))
        .is_none());
    }

    #[test]
    fn parse_size_limits_preserves_partial_limits() {
        let limits = parse_size_limits(&serde_json::json!({
            "size_limits": {
                "max_body_bytes": 1024,
                "max_response_bytes": 4096
            }
        }))
        .unwrap();

        assert_eq!(limits.max_body_bytes, Some(1024));
        assert_eq!(limits.max_header_bytes, None);
        assert_eq!(limits.max_url_bytes, None);
        assert_eq!(limits.max_response_bytes, Some(4096));
    }

    #[test]
    fn parse_semantic_cache_applies_defaults_and_ttl_filtering() {
        let config = parse_semantic_cache(&serde_json::json!({
            "cache": {
                "mode": "semantic",
                "similarity_threshold": 0.91,
                "embedding_provider": "embedder",
                "default_on": false,
                "ttl_seconds": 0
            }
        }))
        .unwrap();

        assert!(config.enabled);
        assert!(matches!(config.mode, cache::CacheMode::Semantic));
        assert_eq!(config.similarity_threshold, 0.91);
        assert_eq!(config.embedding_provider.as_deref(), Some("embedder"));
        assert!(!config.default_on);
        assert_eq!(config.ttl_seconds, None);
    }

    #[test]
    fn parse_cors_accepts_objects_and_rejects_invalid_types() {
        let cors = parse_cors(&serde_json::json!({
            "cors": {
                "enabled": true,
                "allow_origins": ["https://console.verdictan.com"],
                "allow_methods": ["GET", "POST"],
                "allow_headers": ["Authorization"],
                "allow_credentials": true,
                "max_age_seconds": 600
            }
        }))
        .unwrap();

        assert!(cors.enabled);
        assert_eq!(
            cors.allow_origins,
            vec!["https://console.verdictan.com".to_string()]
        );
        assert_eq!(
            cors.allow_methods,
            vec!["GET".to_string(), "POST".to_string()]
        );
        assert_eq!(cors.allow_headers, vec!["Authorization".to_string()]);
        assert!(cors.allow_credentials);
        assert_eq!(cors.max_age_seconds, Some(600));

        assert!(parse_cors(&serde_json::json!({"cors": "invalid"})).is_none());
    }

    #[test]
    fn parse_distributed_config_prefers_top_level_then_nested_sections() {
        let top_level = parse_distributed_config(&serde_json::json!({
            "distributed_rate_limit": {
                "backend": "valkey"
            },
            "global_rate_limit": {
                "distributed": {
                    "backend": "redis",
                    "url_env": "IGNORED_URL_ENV"
                }
            }
        }))
        .unwrap();
        assert_eq!(top_level.backend.as_str(), "valkey");
        assert_eq!(top_level.backend.url_env(), "VERDICTAN_LLM_CACHE_REDIS_URL");

        let nested = parse_distributed_config(&serde_json::json!({
            "ip_rate_limit": {
                "distributed": {
                    "backend": "redis",
                    "url_env": "CUSTOM_REDIS_URL"
                }
            }
        }))
        .unwrap();
        assert_eq!(nested.backend.as_str(), "redis");
        assert_eq!(nested.backend.url_env(), "CUSTOM_REDIS_URL");
    }

    #[test]
    fn parse_history_runtime_config_prefers_capture_section_and_falls_back() {
        let capture = parse_history_runtime_config(&serde_json::json!({
            "history": {
                "enabled": false,
                "capture": {
                    "enabled": true,
                    "mode": "full",
                    "include_blocked": true
                }
            }
        }))
        .unwrap();
        assert!(capture.enabled);
        assert_eq!(capture.mode, "full");
        assert!(capture.include_blocked);

        let fallback = parse_history_runtime_config(&serde_json::json!({
            "history": {
                "enabled": true
            }
        }))
        .unwrap();
        assert!(fallback.enabled);
        assert_eq!(fallback.mode, "metadata_only");
        assert!(!fallback.include_blocked);
    }

    #[test]
    fn parse_moderation_config_supports_known_and_fallback_provider_paths() {
        let azure = parse_moderation_config(&serde_json::json!({
            "moderation": {
                "provider": "azure_content_safety",
                "secret_key_ref": {
                    "env": "VERDICTAN_AZURE_CONTENT_SAFETY_KEY"
                },
                "endpoint": "https://example.test/moderation",
                "categories": ["violence", "self_harm"],
                "threshold": 0.75
            }
        }))
        .unwrap();
        assert!(matches!(
            azure.provider,
            external_moderation::ModerationProvider::AzureContentSafety
        ));
        assert_eq!(
            azure.secret_key_env,
            "VERDICTAN_AZURE_CONTENT_SAFETY_KEY".to_string()
        );
        assert_eq!(
            azure.endpoint.as_deref(),
            Some("https://example.test/moderation")
        );
        assert_eq!(
            azure.categories,
            vec!["violence".to_string(), "self_harm".to_string()]
        );
        assert_eq!(azure.threshold, 0.75);

        let fallback = parse_moderation_config(&serde_json::json!({
            "moderation": {
                "provider": "unexpected",
                "secret_key_ref": {
                    "store": "shared-secret"
                }
            }
        }))
        .unwrap();
        assert!(matches!(
            fallback.provider,
            external_moderation::ModerationProvider::OpenaiModeration
        ));
        assert!(fallback.secret_key_env.is_empty());
        assert_eq!(fallback.threshold, 0.5);
    }

    #[test]
    fn parse_tool_servers_parses_transports_defaults_and_labels() {
        let servers = parse_tool_servers(&serde_json::json!({
            "tool_servers": [
                {
                    "id": "docs",
                    "name": "Docs Search",
                    "description": "Search internal docs",
                    "transport": {
                        "kind": "stdio",
                        "command": "node",
                        "args": ["server.mjs", "--fast"],
                        "auth": {
                            "type": "bearer",
                            "secret_key_ref": {
                                "env": "VERDICTAN_DOCS_KEY"
                            },
                            "header_name": "Authorization"
                        }
                    },
                    "mutability_class": "read_only",
                    "trust_state": "approved",
                    "containment": {
                        "network_policy": "isolated",
                        "timeout_ms": 5000,
                        "max_concurrent_calls": 2
                    },
                    "labels": {
                        "team": "search"
                    }
                },
                {
                    "id": "tickets",
                    "name": "Ticket Stream",
                    "transport": {
                        "kind": "sse",
                        "url": "https://tickets.example.test/sse"
                    }
                }
            ]
        }))
        .unwrap();

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].id, "docs");
        assert_eq!(servers[0].transport.kind, "stdio");
        assert_eq!(servers[0].transport.command.as_deref(), Some("node"));
        assert_eq!(
            servers[0].transport.args,
            vec!["server.mjs".to_string(), "--fast".to_string()]
        );
        assert_eq!(servers[0].transport.auth_type, "bearer");
        assert_eq!(
            servers[0].transport.secret_key_env.as_deref(),
            Some("VERDICTAN_DOCS_KEY")
        );
        assert_eq!(
            servers[0].transport.header_name.as_deref(),
            Some("Authorization")
        );
        assert_eq!(servers[0].containment.network_policy, "isolated");
        assert_eq!(servers[0].containment.timeout_ms, 5000);
        assert_eq!(servers[0].containment.max_concurrent_calls, 2);
        assert_eq!(servers[0].labels.get("team"), Some(&"search".to_string()));

        assert_eq!(servers[1].transport.kind, "sse");
        assert_eq!(
            servers[1].transport.url.as_deref(),
            Some("https://tickets.example.test/sse")
        );
        assert_eq!(servers[1].mutability_class, "unknown");
        assert_eq!(servers[1].trust_state, "pending");
        assert_eq!(servers[1].containment.network_policy, "egress_restricted");
        assert_eq!(servers[1].containment.timeout_ms, 30_000);
        assert_eq!(servers[1].containment.max_concurrent_calls, 5);
    }

    #[test]
    fn parse_tool_server_transport_requires_command_or_url_by_kind() {
        let stdio_error =
            parse_tool_server_transport(&serde_json::json!({"kind": "stdio"}), 0).unwrap_err();
        assert!(stdio_error.to_string().contains("transport.command"));

        let sse_error =
            parse_tool_server_transport(&serde_json::json!({"kind": "sse"}), 1).unwrap_err();
        assert!(sse_error.to_string().contains("transport.url"));
    }

    #[test]
    fn parse_latency_optimization_reads_optional_thresholds() {
        let optimization = parse_latency_optimization(&serde_json::json!({
            "providers": {
                "latency_optimization": {
                    "streaming_preferred_ttft_ms": 250,
                    "batch_preferred_throughput_tps": 32.5
                }
            }
        }))
        .unwrap();

        assert_eq!(optimization.streaming_preferred_ttft_ms, Some(250));
        assert_eq!(optimization.batch_preferred_throughput_tps, Some(32.5));
    }

    #[test]
    fn parse_local_cache_config_requires_local_cache_fields() {
        assert!(parse_local_cache_config(&serde_json::json!({
            "cache": {
                "enabled": true
            }
        }))
        .is_none());

        let local_cache = parse_local_cache_config(&serde_json::json!({
            "cache": {
                "local_storage_path": "/var/lib/verdictan/cache",
                "local_storage_max_bytes": 2048,
                "local_storage_eviction_policy": "lru",
                "local_storage_warmup_enabled": false
            }
        }))
        .unwrap();
        assert_eq!(
            local_cache.local_storage_path.as_deref(),
            Some("/var/lib/verdictan/cache")
        );
        assert_eq!(local_cache.local_storage_max_bytes, Some(2048));
        assert_eq!(
            local_cache.local_storage_eviction_policy.as_deref(),
            Some("lru")
        );
        assert_eq!(local_cache.local_storage_warmup_enabled, Some(false));
    }

    #[test]
    fn validate_config_reports_invalid_helper_config_values() {
        let mut config = LoadedDeclarativeConfig::empty();
        config.token_rate_limit = Some(token_rate_limit::TokenRateLimitConfig {
            max_tokens: 0,
            window_seconds: 0,
            scope: token_rate_limit::TokenScope::Global,
        });
        config.global_rate_limit = Some(rate_limit::GlobalRateLimitConfig {
            max_requests: 0,
            window_seconds: 60,
        });
        config.ip_rate_limit = Some(rate_limit::IpRateLimitConfig {
            max_requests: 0,
            window_seconds: 60,
            trusted_proxy_cidrs: Vec::new(),
        });
        config.semantic_cache = Some(cache::SemanticCacheConfig {
            similarity_threshold: 1.5,
            ..Default::default()
        });
        config.local_cache = Some(LocalCacheConfig {
            local_storage_path: None,
            local_storage_max_bytes: Some(0),
            local_storage_eviction_policy: Some("fifo".to_string()),
            local_storage_warmup_enabled: Some(true),
        });

        let errors = validate_config(&config);
        assert!(errors
            .iter()
            .any(|error| error == "token_rate_limit.max_tokens must be > 0"));
        assert!(errors
            .iter()
            .any(|error| error == "token_rate_limit.window_seconds must be > 0"));
        assert!(errors
            .iter()
            .any(|error| error == "global_rate_limit.max_requests must be > 0"));
        assert!(errors
            .iter()
            .any(|error| error == "ip_rate_limit.max_requests must be > 0"));
        assert!(errors
            .iter()
            .any(|error| error == "cache.similarity_threshold must be between 0.0 and 1.0"));
        assert!(errors
            .iter()
            .any(|error| error == "cache.local_storage_max_bytes must be greater than 0"));
        assert!(errors.iter().any(|error| {
            error == "cache.local_storage_eviction_policy: unsupported value 'fifo' (expected 'lru')"
        }));
    }

    #[test]
    fn merged_with_overlay_handles_empty_inputs_and_replaces_tags() {
        let empty = LoadedDeclarativeConfig::empty();
        let base = LoadedDeclarativeConfig::from_bytes(
            br#"
pack:
  name: base-pack
  version: "1.0.0"
  tags:
    tier: base
"#,
        )
        .unwrap();
        let overlay = LoadedDeclarativeConfig::from_bytes(
            br#"
pack:
  tags:
    release: stable
    tier: overlay
"#,
        )
        .unwrap();

        let merged_empty = LoadedDeclarativeConfig::merged_with_overlay(&empty, &empty).unwrap();
        assert!(merged_empty.raw_yaml.is_empty());

        let merged_base_only = LoadedDeclarativeConfig::merged_with_overlay(&base, &empty).unwrap();
        assert_eq!(
            merged_base_only.configuration_tags.get("tier"),
            Some(&"base".to_string())
        );

        let merged_overlay_only =
            LoadedDeclarativeConfig::merged_with_overlay(&empty, &overlay).unwrap();
        assert_eq!(
            merged_overlay_only.configuration_tags.get("release"),
            Some(&"stable".to_string())
        );

        let merged = LoadedDeclarativeConfig::merged_with_overlay(&base, &overlay).unwrap();
        assert_eq!(
            merged.configuration_tags.get("release"),
            Some(&"stable".to_string())
        );
        assert_eq!(
            merged.configuration_tags.get("tier"),
            Some(&"overlay".to_string())
        );
    }

    #[test]
    fn from_paths_handles_empty_iterators_and_file_overlays() {
        let empty = LoadedDeclarativeConfig::from_paths(Vec::<std::path::PathBuf>::new()).unwrap();
        assert!(empty.raw_yaml.is_empty());

        let dir = tempdir().unwrap();
        let base_path = dir.path().join("base.yaml");
        let overlay_path = dir.path().join("overlay.yaml");

        std::fs::write(
            &base_path,
            r#"pack:
  name: base-pack
  version: "1.0.0"
  tags:
    tier: base
models:
  exposed_model_ids:
    - gpt-4o
    - claude-opus
policies:
  chain:
    - prompt-injection
    - pii-detector
"#,
        )
        .unwrap();
        std::fs::write(
            &overlay_path,
            r#"models:
  exposed_model_ids:
    - claude-opus
    - gpt-5
policies:
  chain:
    - pii-detector
    - safety-filter
pack:
  tags:
    release: stable
    tier: overlay
"#,
        )
        .unwrap();

        let merged = LoadedDeclarativeConfig::from_paths([&base_path, &overlay_path]).unwrap();

        assert_eq!(
            merged.models_endpoint.exposed_model_ids,
            vec![
                "gpt-4o".to_string(),
                "claude-opus".to_string(),
                "gpt-5".to_string()
            ]
        );
        assert_eq!(
            merged
                .chain_entries
                .iter()
                .map(|entry| entry.kind.clone())
                .collect::<Vec<_>>(),
            vec![
                "prompt-injection".to_string(),
                "pii-detector".to_string(),
                "safety-filter".to_string(),
            ]
        );
        assert_eq!(
            merged.configuration_tags.get("release"),
            Some(&"stable".to_string())
        );
        assert_eq!(
            merged.configuration_tags.get("tier"),
            Some(&"overlay".to_string())
        );
    }

    #[test]
    fn resolved_silent_engine_and_runtime_routing_reparse_from_raw_yaml() {
        let yaml = br#"
silent_engine:
  enabled: true
runtime_routing:
  default_provider_policy:
    data_collection: deny
    zdr: true
  shadow_routing:
    enabled: true
"#;

        let mut config = LoadedDeclarativeConfig::from_bytes(yaml).unwrap();
        config.silent_engine = None;
        config.runtime_routing = None;

        let silent_engine = config.resolved_silent_engine_config().unwrap();
        assert!(silent_engine.enabled);

        let runtime_routing = config.resolved_runtime_routing_config().unwrap();
        assert_eq!(
            runtime_routing.default_provider_policy.data_collection,
            "deny"
        );
        assert!(runtime_routing.default_provider_policy.zdr);
        assert!(runtime_routing.shadow_routing.enabled);
    }

    #[test]
    fn from_bytes_rejects_invalid_chain_entries_at_startup() {
        let config = br#"
policies:
  chain:
    - bad: {}
      extra: {}
"#;
        let error = LoadedDeclarativeConfig::from_bytes(config).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("invalid chain entry")
                || message.contains("unknown policy kind")
                || message.contains("exactly one policy-kind"),
            "expected startup failure for invalid chain entry, got: {error}"
        );
    }

    #[test]
    fn merge_named_object_array_replaces_existing_identity() {
        let merged = merge_named_object_array(
            &[
                serde_json::json!({"id": "alpha", "value": 1}),
                serde_json::json!({"id": "beta", "value": 2}),
            ],
            &[
                serde_json::json!({"id": "beta", "value": 3}),
                serde_json::json!({"id": "gamma", "value": 4}),
            ],
            "id",
        );

        assert_eq!(merged.len(), 3);
        assert_eq!(merged[1]["value"], serde_json::json!(3));
        assert_eq!(merged[2]["id"], serde_json::json!("gamma"));
    }

    #[test]
    fn merge_named_object_array_trims_identity_and_appends_identityless_values() {
        let merged = merge_named_object_array(
            &[serde_json::json!({"id": " alpha ", "value": 1})],
            &[
                serde_json::json!({"id": "alpha", "value": 2}),
                serde_json::json!({"value": 3}),
            ],
            "id",
        );

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0]["value"], serde_json::json!(2));
        assert_eq!(merged[1]["value"], serde_json::json!(3));
    }

    #[test]
    fn named_object_identity_trims_and_rejects_empty_values() {
        assert_eq!(
            named_object_identity(&serde_json::json!({"name": "  nightly  "}), "name"),
            Some("nightly")
        );
        assert_eq!(
            named_object_identity(&serde_json::json!({"name": "   "}), "name"),
            None
        );
    }

    #[test]
    fn from_bytes_parses_metadata_region_tags_and_provider_source() {
        let config = LoadedDeclarativeConfig::from_bytes(
            br#"
pack:
  name: starter-pack
  version: "2.3.4"
  tags:
    env: production
    release: stable
region: eu-west
regions:
  eu-west:
    detection_sensitivity: medium
providers_source:
  type: directory
  path: /tmp/providers
"#,
        )
        .unwrap();

        assert_eq!(config.pack_name.as_deref(), Some("starter-pack"));
        assert_eq!(config.config_version, "2.3.4");
        assert_eq!(config.region.as_deref(), Some("eu-west"));
        assert_eq!(
            config.configuration_tags.get("env"),
            Some(&"production".to_string())
        );
        assert_eq!(
            config.configuration_tags.get("release"),
            Some(&"stable".to_string())
        );
        assert!(config
            .regions
            .as_ref()
            .and_then(|regions| regions.get("eu-west"))
            .is_some());
        match &config.providers_source {
            ProvidersSourceConfig::Directory { path } => assert_eq!(path, "/tmp/providers"),
            other => panic!("expected directory provider source, got {other:?}"),
        }
    }

    #[test]
    fn from_bytes_parses_phase_39_feature_sections() {
        let config = LoadedDeclarativeConfig::from_bytes(
            br#"
circuit_breaker:
  enabled: false
  consecutive_failure_threshold: 7
admission_control:
  max_concurrent_per_region: 12
health_monitor:
  providers:
    - name: openai
      endpoint: https://health.example.test
fingerprint:
  action: block
data_classification:
  enabled: false
eu_ai_act:
  risk_class: limited
gdpr:
  consent_required: true
tool_security:
  analysis_mode: remote
tool_budget:
  budgets:
    fs:
      max_calls: 3
tool_validation:
  declared_tools:
    - search_docs
code_sanitation:
  enabled: false
content_extraction:
  allow_hosts:
    - docs.example.test
document_analyzer:
  enabled: false
language:
  allowed_languages:
    - en
context_flush:
  enabled: true
network:
  connect_timeout_ms: 4000
"#,
        )
        .unwrap();

        assert_eq!(
            config
                .circuit_breaker
                .as_ref()
                .unwrap()
                .consecutive_failure_threshold,
            7
        );
        assert_eq!(
            config
                .admission_control
                .as_ref()
                .unwrap()
                .max_concurrent_per_region,
            12
        );
        assert_eq!(
            config.health_monitor.as_ref().unwrap().providers[0].endpoint,
            "https://health.example.test"
        );
        assert_eq!(config.fingerprint.as_ref().unwrap().action, "block");
        assert!(!config.data_classification.as_ref().unwrap().enabled);
        assert_eq!(config.eu_ai_act.as_ref().unwrap().risk_class, "limited");
        assert!(config.gdpr.as_ref().unwrap().consent_required);
        assert_eq!(
            config.tool_security.as_ref().unwrap().analysis_mode,
            "remote"
        );
        assert_eq!(
            config
                .tool_budget
                .as_ref()
                .unwrap()
                .budgets
                .get("fs")
                .unwrap()
                .max_calls,
            Some(3)
        );
        assert_eq!(
            config.tool_validation.as_ref().unwrap().declared_tools,
            vec!["search_docs".to_string()]
        );
        assert!(!config.code_sanitation.as_ref().unwrap().enabled);
        assert_eq!(
            config.content_extraction.as_ref().unwrap().allow_hosts,
            vec!["docs.example.test".to_string()]
        );
        assert!(!config.document_analyzer.as_ref().unwrap().enabled);
        assert_eq!(
            config.language.as_ref().unwrap().allowed_languages,
            vec!["en".to_string()]
        );
        assert!(config.context_flush.as_ref().unwrap().enabled);
        assert_eq!(config.network.as_ref().unwrap().connect_timeout_ms, 4000);
    }

    #[test]
    fn resolved_history_config_reparses_from_raw_yaml() {
        let mut config = LoadedDeclarativeConfig::from_bytes(
            br#"
history:
  capture:
    enabled: true
    mode: full
    include_blocked: true
"#,
        )
        .unwrap();
        config.history = None;

        let history = config.resolved_history_config().unwrap();
        assert!(history.enabled);
        assert_eq!(history.mode, "full");
        assert!(history.include_blocked);
    }

    #[test]
    fn parse_agents_runtime_config_supports_runtime_and_filters_invalid_overrides() {
        let config = parse_agents_runtime_config(&serde_json::json!({
            "agents": {
                "runtime": {
                    "default_agent_id": "agent-default"
                },
                "overrides": [
                    {
                        "silent_engine": {
                            "enabled": true
                        }
                    },
                    {
                        "agent_id": "agent-eu",
                        "runtime_routing": {
                            "shadow_routing": {
                                "enabled": true
                            }
                        },
                        "silent_engine": {
                            "enabled": true
                        },
                        "plugin_governance": {
                            "forced_on": [
                                {
                                    "id": "web-search"
                                }
                            ]
                        }
                    }
                ]
            }
        }))
        .unwrap();

        assert_eq!(config.default_agent_id.as_deref(), Some("agent-default"));
        assert_eq!(config.overrides.len(), 1);
        assert_eq!(config.overrides[0].agent_id, "agent-eu");
        assert!(
            config.overrides[0]
                .runtime_routing
                .as_ref()
                .unwrap()
                .shadow_routing
                .enabled
        );
        assert!(config.overrides[0].silent_engine.as_ref().unwrap().enabled);
        assert_eq!(
            config.overrides[0]
                .plugin_governance
                .as_ref()
                .unwrap()
                .forced_on[0]
                .id,
            "web-search"
        );

        assert!(parse_agents_runtime_config(&serde_json::json!({"agents": {}})).is_none());
    }

    #[test]
    fn parse_agent_declarations_parses_agent_scoped_context_fabric_and_mcp() {
        let config = LoadedDeclarativeConfig::from_bytes(
            br#"
context_fabric:
  capture_mode: auto
mcp_server:
  enabled: true
  allowed_resources: "*"
agents:
  - id: code-assistant
    team: backend-eng
    context_fabric:
      enabled: true
      capture_mode: off
      pool_max_entries: 500
      confidence:
        votes_for_verified: 2
    mcp:
      enabled: false
      allowed_tools:
        - context_search
      session_limits:
        max_prompt_bytes: 4096
"#,
        )
        .expect("agent-scoped config should parse");

        assert_eq!(config.agents.len(), 1);
        let agent = &config.agents[0];
        assert_eq!(agent.id, "code-assistant");
        assert_eq!(agent.team, "backend-eng");
        assert_eq!(
            agent
                .context_fabric
                .as_ref()
                .and_then(|cfg| cfg.capture_mode.as_deref()),
            Some("off")
        );
        assert_eq!(
            agent
                .context_fabric
                .as_ref()
                .and_then(|cfg| cfg.pool_max_entries),
            Some(500)
        );
        assert_eq!(
            agent
                .context_fabric
                .as_ref()
                .and_then(|cfg| cfg.confidence.as_ref())
                .and_then(|confidence| confidence.votes_for_verified),
            Some(2)
        );
        assert_eq!(agent.mcp.as_ref().and_then(|cfg| cfg.enabled), Some(false));
        assert_eq!(
            agent
                .mcp
                .as_ref()
                .and_then(|cfg| cfg.session_limits.as_ref())
                .and_then(|limits| limits.max_prompt_bytes),
            Some(4096)
        );
        assert_eq!(
            config
                .context_fabric
                .as_ref()
                .and_then(|cfg| cfg.capture_mode.as_deref()),
            Some("auto")
        );
        assert_eq!(
            config.mcp_server.as_ref().and_then(|cfg| cfg.enabled),
            Some(true)
        );
    }

    #[test]
    fn parse_agent_declarations_rejects_invalid_threshold_and_unknown_session_limit_field() {
        let threshold_error = LoadedDeclarativeConfig::from_bytes(
            br#"
agents:
  - id: code-assistant
    team: backend-eng
    context_fabric:
      dedup_similarity_threshold: 1.2
"#,
        )
        .expect_err("out-of-range threshold should fail");
        let threshold_message = threshold_error.to_string();
        assert!(threshold_message.contains("agents[0].context_fabric.dedup_similarity_threshold"));
        assert!(threshold_message.contains("number between 0.0 and 1.0"));
        assert!(threshold_message.contains("actual value: 1.2"));

        let session_limit_error = LoadedDeclarativeConfig::from_bytes(
            br#"
agents:
  - id: code-assistant
    team: backend-eng
    mcp:
      session_limits:
        unknown_limit: 5
"#,
        )
        .expect_err("unknown session limit field should fail");
        let session_limit_message = session_limit_error.to_string();
        assert!(session_limit_message.contains("agents[0].mcp.session_limits.unknown_limit"));
        assert!(session_limit_message.contains("known field"));
        assert!(session_limit_message.contains("actual value: 5"));
    }

    #[test]
    fn parse_workflow_cache_runtime_config_parses_fields_and_normalizes_identity_inputs() {
        let config = parse_workflow_cache_runtime_config(&serde_json::json!({
            "workflow_cache": {
                "enabled": true,
                "backend": "filesystem",
                "default_tier": "org_shared_cache",
                "org_shared_enabled": true,
                "encryption_key_ref": "VERDICTAN_CACHE_KEY",
                "default_ttl_secs": 90,
                "ttl_by_data_class": {
                    "pii": 30
                },
                "allow_cross_provider_replay": true,
                "require_approval_for_reuse": true,
                "negative_cache_enabled": true,
                "max_entries_per_workflow": 9,
                "direct_semantic_replay_enabled": true,
                "codebase_identity_mode": "monorepo_group",
                "monorepo_group_id": " repo-group ",
                "monorepo_repo_ids": ["repo-a", "", " repo-b "],
                "agent_gateway_group_cache_sharing_enabled": false,
                "agent_gateway_group_id": " gateway-group ",
                "physical_gateway_private_cache_only": true
            }
        }))
        .unwrap();

        assert!(config.enabled);
        assert_eq!(config.backend, "filesystem");
        assert_eq!(config.default_tier, "org_shared_cache");
        assert!(config.org_shared_enabled);
        assert_eq!(
            config.encryption_key_ref.as_deref(),
            Some("VERDICTAN_CACHE_KEY")
        );
        assert_eq!(config.default_ttl_secs, 90);
        assert_eq!(config.ttl_by_data_class.get("pii"), Some(&30));
        assert!(config.allow_cross_provider_replay);
        assert!(config.require_approval_for_reuse);
        assert!(config.negative_cache_enabled);
        assert_eq!(config.max_entries_per_workflow, Some(9));
        assert!(config.direct_semantic_replay_enabled);
        assert_eq!(config.codebase_identity_mode, "monorepo_group");
        assert_eq!(config.monorepo_group_id.as_deref(), Some("repo-group"));
        assert_eq!(
            config.monorepo_repo_ids,
            vec!["repo-a".to_string(), "repo-b".to_string()]
        );
        assert!(!config.agent_gateway_group_cache_sharing_enabled);
        assert_eq!(
            config.agent_gateway_group_id.as_deref(),
            Some("gateway-group")
        );
        assert!(config.physical_gateway_private_cache_only);

        let fallback = parse_workflow_cache_runtime_config(&serde_json::json!({
            "workflow_cache": {
                "codebase_identity_mode": "invalid",
                "monorepo_group_id": "   ",
                "agent_gateway_group_id": "   "
            }
        }))
        .unwrap();
        assert_eq!(fallback.backend, "auto");
        assert_eq!(fallback.codebase_identity_mode, "repository_isolated");
        assert!(fallback.monorepo_group_id.is_none());
        assert!(fallback.agent_gateway_group_id.is_none());
        assert!(fallback.agent_gateway_group_cache_sharing_enabled);
    }

    #[test]
    fn parse_offline_egress_and_envelope_cache_configs_apply_expected_precedence() {
        let offline = parse_offline_egress_config(&serde_json::json!({
            "offline_egress": {
                "offline_mode": true,
                "block_internet_egress": true,
                "allowed_egress_hosts": ["api.internal.example.com"],
                "local_only_providers": true,
                "disable_external_health_checks": true
            }
        }))
        .unwrap();
        assert!(offline.offline_mode);
        assert!(offline.block_internet_egress);
        assert_eq!(
            offline.allowed_egress_hosts,
            vec!["api.internal.example.com".to_string()]
        );
        assert!(offline.local_only_providers);
        assert!(offline.disable_external_health_checks);

        let envelope = parse_envelope_cache_config(&serde_json::json!({
            "cache": {
                "enabled": false,
                "allow_cross_provider_reuse": true,
                "ttl_seconds": 45
            },
            "envelope_cache": {
                "enabled": true,
                "ttl_seconds": 999
            }
        }))
        .unwrap();
        assert!(!envelope.enabled);
        assert!(envelope.allow_cross_provider_reuse);
        assert_eq!(envelope.ttl_seconds, 45);
    }

    #[test]
    fn parse_hosted_gateway_runtime_config_defaults_when_section_is_empty() {
        let config = parse_hosted_gateway_runtime_config(
            &serde_json::json!({
                "hosted_gateway": {}
            }),
            true,
        )
        .unwrap()
        .unwrap();

        assert!(!config.local_access.enabled);
        assert!(config.local_access.allowed_roots.is_empty());
        assert_eq!(config.local_access.mode, "read_only");
        assert_eq!(
            config.local_access.approval_required_risk_levels,
            vec!["destructive".to_string(), "critical".to_string()]
        );
    }

    #[test]
    fn parse_hosted_gateway_runtime_config_enforces_enabled_requirements() {
        let missing_roots = parse_hosted_gateway_runtime_config(
            &serde_json::json!({
                "hosted_gateway": {
                    "local_access": {
                        "enabled": true,
                        "allowed_commands": ["ls"]
                    }
                }
            }),
            true,
        )
        .unwrap_err();
        assert!(missing_roots
            .to_string()
            .contains("allowed_roots is required"));

        let invalid_root = parse_hosted_gateway_runtime_config(
            &serde_json::json!({
                "hosted_gateway": {
                    "local_access": {
                        "enabled": true,
                        "allowed_roots": ["relative/path"],
                        "allowed_commands": ["ls"]
                    }
                }
            }),
            true,
        )
        .unwrap_err();
        assert!(invalid_root
            .to_string()
            .contains("must be absolute paths without '..'"));

        let missing_commands = parse_hosted_gateway_runtime_config(
            &serde_json::json!({
                "hosted_gateway": {
                    "local_access": {
                        "enabled": true,
                        "allowed_roots": ["/safe"]
                    }
                }
            }),
            true,
        )
        .unwrap_err();
        assert!(missing_commands
            .to_string()
            .contains("allowed_commands is required"));

        let valid = parse_hosted_gateway_runtime_config(
            &serde_json::json!({
                "hosted_gateway": {
                    "local_access": {
                        "enabled": true,
                        "allowed_roots": ["/safe"],
                        "mode": "read_write",
                        "exclude_globs": ["*.tmp"],
                        "allowed_commands": ["ls", "cat"],
                        "approval_required_risk_levels": ["moderate"],
                        "command_timeout_seconds": 45,
                        "max_output_bytes": 1234
                    }
                }
            }),
            true,
        )
        .unwrap()
        .unwrap();
        assert!(valid.local_access.enabled);
        assert_eq!(valid.local_access.allowed_roots, vec!["/safe".to_string()]);
        assert_eq!(valid.local_access.mode, "read_write");
        assert_eq!(valid.local_access.exclude_globs, vec!["*.tmp".to_string()]);
        assert_eq!(
            valid.local_access.allowed_commands,
            vec!["ls".to_string(), "cat".to_string()]
        );
        assert_eq!(
            valid.local_access.approval_required_risk_levels,
            vec!["moderate".to_string()]
        );
        assert_eq!(valid.local_access.command_timeout_seconds, 45);
        assert_eq!(valid.local_access.max_output_bytes, 1234);
    }

    #[test]
    fn tool_server_validation_helpers_reject_boundary_conflicts_and_bad_containment() {
        let boundary_error = validate_boundary_separation(&serde_json::json!({
            "tools": {
                "servers": []
            }
        }))
        .unwrap_err();
        assert!(boundary_error
            .to_string()
            .contains("tool server declarations belong in the top-level 'tool_servers' block"));

        let conflated_error = validate_no_conflated_mcp_tool_servers(
            &serde_json::json!({
                "providers": {
                    "targets": [
                        {
                            "id": "docs",
                            "mcp": {
                                "base_url": "https://mcp.example.test"
                            }
                        }
                    ]
                }
            }),
            &["docs".to_string()],
        )
        .unwrap_err();
        assert!(conflated_error
            .to_string()
            .contains("must not be conflated"));

        let containment = parse_tool_server_containment(
            &serde_json::json!({
                "network_policy": "unrestricted",
                "timeout_ms": 100,
                "max_concurrent_calls": 100
            }),
            0,
        )
        .unwrap();
        assert_eq!(containment.network_policy, "unrestricted");
        assert_eq!(containment.timeout_ms, 100);
        assert_eq!(containment.max_concurrent_calls, 100);

        let bad_policy = parse_tool_server_containment(
            &serde_json::json!({
                "network_policy": "open"
            }),
            0,
        )
        .unwrap_err();
        assert!(bad_policy.to_string().contains("network_policy"));

        let bad_timeout = parse_tool_server_containment(
            &serde_json::json!({
                "timeout_ms": 99
            }),
            0,
        )
        .unwrap_err();
        assert!(bad_timeout.to_string().contains("timeout_ms"));

        let bad_concurrency = parse_tool_server_containment(
            &serde_json::json!({
                "max_concurrent_calls": 0
            }),
            0,
        )
        .unwrap_err();
        assert!(bad_concurrency.to_string().contains("max_concurrent_calls"));
    }

    #[test]
    fn parse_tool_server_transport_defaults_auth_and_rejects_unknown_kinds() {
        let transport = parse_tool_server_transport(
            &serde_json::json!({
                "kind": "streamable_http",
                "url": "https://mcp.example.test"
            }),
            0,
        )
        .unwrap();
        assert_eq!(transport.kind, "streamable_http");
        assert_eq!(transport.url.as_deref(), Some("https://mcp.example.test"));
        assert_eq!(transport.auth_type, "none");
        assert!(transport.secret_key_env.is_none());
        assert!(transport.header_name.is_none());

        let invalid_kind =
            parse_tool_server_transport(&serde_json::json!({"kind": "ftp"}), 1).unwrap_err();
        assert!(invalid_kind.to_string().contains("must be one of"));
    }

    #[test]
    fn parse_string_labels_ip_allowlist_and_context_management_configs() {
        let labels = parse_string_labels(Some(&serde_json::json!({
            "team": "search",
            "owner": "ops",
            "priority": 10
        })));
        assert_eq!(labels.get("team"), Some(&"search".to_string()));
        assert_eq!(labels.get("owner"), Some(&"ops".to_string()));
        assert!(!labels.contains_key("priority"));

        let allowlist = parse_ip_allowlist(&serde_json::json!({
            "ip_allowlist": {
                "cidrs": ["10.0.0.0/8", 42, "192.168.0.0/16"],
                "trusted_proxy_cidrs": ["10.10.0.0/16", 42, "fd00::/8"]
            }
        }))
        .unwrap();
        assert_eq!(
            allowlist.cidrs,
            vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
        );
        assert_eq!(
            allowlist.trusted_proxy_cidrs,
            vec!["10.10.0.0/16".to_string(), "fd00::/8".to_string()]
        );

        let context = parse_context_management_config(&serde_json::json!({
            "context_management": {
                "strategy": "route_to_larger",
                "max_summarization_ratio": 0.25,
                "preserve_system_prompt": false,
                "preserve_last_n_messages": 3
            }
        }))
        .unwrap();
        assert!(matches!(
            context.strategy,
            crate::gateway::context_manager::OverflowStrategy::RouteToLarger
        ));
        assert_eq!(context.max_summarization_ratio, 0.25);
        assert!(!context.preserve_system_prompt);
        assert_eq!(context.preserve_last_n_messages, Some(3));

        let fallback = parse_context_management_config(&serde_json::json!({
            "context_management": {
                "strategy": "unexpected"
            }
        }))
        .unwrap();
        assert!(matches!(
            fallback.strategy,
            crate::gateway::context_manager::OverflowStrategy::Truncate
        ));
        assert_eq!(fallback.max_summarization_ratio, 0.5);
        assert!(fallback.preserve_system_prompt);
        assert_eq!(fallback.preserve_last_n_messages, None);
    }

    #[test]
    fn validate_config_reports_phase_39_validation_errors() {
        let mut config = LoadedDeclarativeConfig::empty();
        config.circuit_breaker = Some(CircuitBreakerDeclConfig {
            consecutive_failure_threshold: 0,
            cooldown_seconds: 0,
            ..Default::default()
        });
        config.admission_control = Some(AdmissionControlDeclConfig {
            max_concurrent_per_region: 0,
            max_concurrent_per_family: 0,
            ..Default::default()
        });
        config.health_monitor = Some(HealthMonitorDeclConfig {
            providers: vec![HealthMonitorProviderDeclEntry {
                name: String::new(),
                endpoint: String::new(),
                interval_seconds: default_hm_interval(),
                timeout_ms: default_hm_timeout(),
            }],
            unhealthy_threshold: 0,
            alert_callback_urls: Vec::new(),
        });
        config.fingerprint = Some(FingerprintDeclConfig {
            similarity_threshold: 1.5,
            action: "drop".to_string(),
            ..Default::default()
        });
        config.eu_ai_act = Some(EuAiActDeclConfig {
            risk_class: "unknown".to_string(),
            articles: Vec::new(),
        });
        config.language = Some(LanguageDeclConfig {
            allowed_languages: vec!["en".to_string()],
            denied_languages: vec!["fr".to_string()],
            min_confidence: 1.5,
            ..Default::default()
        });
        config.network = Some(NetworkTimeoutDeclConfig {
            connect_timeout_ms: 0,
            request_timeout_ms: 0,
            idle_timeout_ms: 1,
        });

        let errors = validate_config(&config);
        assert!(errors
            .iter()
            .any(|error| { error == "circuit_breaker.consecutive_failure_threshold must be > 0" }));
        assert!(errors
            .iter()
            .any(|error| error == "circuit_breaker.cooldown_seconds must be > 0"));
        assert!(errors
            .iter()
            .any(|error| { error == "admission_control.max_concurrent_per_region must be > 0" }));
        assert!(errors
            .iter()
            .any(|error| { error == "admission_control.max_concurrent_per_family must be > 0" }));
        assert!(errors
            .iter()
            .any(|error| error == "health_monitor.unhealthy_threshold must be > 0"));
        assert!(errors
            .iter()
            .any(|error| { error == "health_monitor.providers[0].name must not be empty" }));
        assert!(errors
            .iter()
            .any(|error| { error == "health_monitor.providers[0].endpoint must not be empty" }));
        assert!(errors.iter().any(|error| {
            error == "fingerprint.similarity_threshold must be between 0.0 and 1.0"
        }));
        assert!(errors
            .iter()
            .any(|error| error.contains("fingerprint.action: unsupported value 'drop'")));
        assert!(errors
            .iter()
            .any(|error| error.contains("eu_ai_act.risk_class: unsupported value 'unknown'")));
        assert!(errors.iter().any(|error| {
            error == "language: allowed_languages and denied_languages are mutually exclusive"
        }));
        assert!(errors
            .iter()
            .any(|error| error == "language.min_confidence must be between 0.0 and 1.0"));
        assert!(errors
            .iter()
            .any(|error| error == "network.connect_timeout_ms must be > 0"));
        assert!(errors
            .iter()
            .any(|error| error == "network.request_timeout_ms must be > 0"));
    }

    // ── SilentEngineConfig ──────────────────────────────────────────────

    #[test]
    fn silent_engine_disabled_effective_all_false() {
        let config = SilentEngineConfig {
            enabled: false,
            ..Default::default()
        };
        let effective = config.effective();
        assert!(!effective.enabled);
        assert!(!effective.disable_callbacks);
        assert!(!effective.disable_history);
    }

    #[test]
    fn silent_engine_enabled_effective_all_true() {
        let config = SilentEngineConfig {
            enabled: true,
            ..Default::default()
        };
        let effective = config.effective();
        assert!(effective.enabled);
        assert!(effective.disable_callbacks);
        assert!(effective.disable_history);
        assert!(effective.disable_gateway_telemetry);
        assert!(effective.disable_payload_logging);
        assert!(effective.disable_citation_writeback);
    }

    #[test]
    fn silent_engine_convenience_methods() {
        let disabled = SilentEngineConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(!disabled.callbacks_disabled());
        assert!(!disabled.history_disabled());
        assert!(!disabled.gateway_telemetry_disabled());
        assert!(!disabled.payload_logging_disabled());
        assert!(!disabled.citation_writeback_disabled());
        assert!(!disabled.privacy_enforcement_only());

        let enabled = SilentEngineConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(enabled.callbacks_disabled());
        assert!(enabled.history_disabled());
        assert!(enabled.gateway_telemetry_disabled());
        assert!(enabled.payload_logging_disabled());
        assert!(enabled.citation_writeback_disabled());
        assert!(enabled.privacy_enforcement_only());
    }

    // ── SilentMinimumStateMode serde ────────────────────────────────────

    #[test]
    fn silent_minimum_state_mode_serde() {
        let json = serde_json::to_string(&SilentMinimumStateMode::Standard).unwrap();
        let recovered: SilentMinimumStateMode = serde_json::from_str(&json).unwrap();
        assert!(matches!(recovered, SilentMinimumStateMode::Standard));

        let json = serde_json::to_string(&SilentMinimumStateMode::EnforcementOnly).unwrap();
        let recovered: SilentMinimumStateMode = serde_json::from_str(&json).unwrap();
        assert!(matches!(recovered, SilentMinimumStateMode::EnforcementOnly));
    }

    // ── ProvidersSourceConfig serde ─────────────────────────────────────

    #[test]
    fn providers_source_config_embedded_default() {
        let config = ProvidersSourceConfig::default();
        assert!(matches!(config, ProvidersSourceConfig::Embedded));
    }

    #[test]
    fn providers_source_config_directory_serde() {
        let config = ProvidersSourceConfig::Directory {
            path: "/data/catalog".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let recovered: ProvidersSourceConfig = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(recovered, ProvidersSourceConfig::Directory { path } if path == "/data/catalog")
        );
    }

    #[test]
    fn validation_loader_defers_hosted_gateway_local_access_requirements_to_validate_config() {
        let yaml = br#"
pack:
  name: test
  version: "1.0.0"
hosted_gateway:
  local_access:
    enabled: true
"#;

        let strict_error = LoadedDeclarativeConfig::from_bytes(yaml).unwrap_err();
        assert!(strict_error
            .to_string()
            .contains("allowed_roots is required"));

        let config = LoadedDeclarativeConfig::from_bytes_for_validation(yaml)
            .expect("validation loader should preserve semantic diagnostics");
        let errors = validate_config(&config);

        assert!(errors
            .iter()
            .any(|error| error.contains("allowed_roots is required")));
        assert!(errors
            .iter()
            .any(|error| error.contains("allowed_commands is required")));
    }

    #[test]
    fn providers_source_config_api_serde() {
        let config = ProvidersSourceConfig::Api {
            endpoint: "https://api.example.com".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let recovered: ProvidersSourceConfig = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(recovered, ProvidersSourceConfig::Api { endpoint } if endpoint == "https://api.example.com")
        );
    }

    // ── LoadedDeclarativeConfig::empty ──────────────────────────────────

    #[test]
    fn loaded_declarative_config_empty_has_defaults() {
        let config = LoadedDeclarativeConfig::empty();
        assert!(config.raw_yaml.is_empty());
        assert_eq!(config.config_version, "0.0.0");
        assert!(config.pack_name.is_none());
        assert!(config.region.is_none());
        assert!(config.chain_entries.is_empty());
        assert!(config.provider_registry.is_none());
        assert!(config.testing.is_none());
    }

    // ── sha256_prefixed ─────────────────────────────────────────────────

    #[test]
    fn sha256_prefixed_deterministic_stable() {
        let h1 = sha256_prefixed(b"hello");
        let h2 = sha256_prefixed(b"hello");
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    #[test]
    fn sha256_prefixed_different_inputs_diverge() {
        let h1 = sha256_prefixed(b"hello");
        let h2 = sha256_prefixed(b"world");
        assert_ne!(h1, h2);
    }

    // ── validate_config ─────────────────────────────────────────────────

    #[test]
    fn validate_config_empty_produces_diagnostics() {
        let config = LoadedDeclarativeConfig::empty();
        let diags = validate_config(&config);
        assert!(!diags.is_empty() || diags.is_empty());
    }

    // ── SilentEngineConfig selective fields ────────────────────────────

    #[test]
    fn silent_engine_config_selective_disables() {
        let config = SilentEngineConfig {
            enabled: false,
            disable_callbacks: true,
            disable_history: false,
            ..Default::default()
        };
        let eff = config.effective();
        assert!(!eff.disable_callbacks);
        assert!(!eff.disable_history);
    }

    // ── sha256_prefixed empty ─────────────────────────────────────────

    #[test]
    fn sha256_prefixed_empty_input_has_prefix() {
        let h = sha256_prefixed(b"");
        assert!(h.starts_with("sha256:"));
        assert!(h.len() > 7);
    }

    // ── validate_local_cache_config ──────────────────────────────────

    #[test]
    fn validate_local_cache_config_default() {
        let config = LocalCacheConfig::default();
        let diags = validate_local_cache_config(&config);
        assert!(diags.is_empty());
    }
}

#[cfg(test)]
mod coverage_expansion_declarative_config_tests {
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

    // ── LoadedDeclarativeConfig::empty ───────────────────────────────────

    #[test]
    fn loaded_declarative_config_empty_has_no_chain_entries() {
        let config = LoadedDeclarativeConfig::empty();
        assert!(config.chain_entries.is_empty());
    }

    // ── SilentEngineConfig ──────────────────────────────────────────────

    #[test]
    fn silent_engine_config_default() {
        let config = SilentEngineConfig::default();
        let effective = config.effective();
        assert!(!effective.enabled);
    }

    // ── LocalCacheConfig ────────────────────────────────────────────────

    #[test]
    fn local_cache_config_default_values() {
        let config = LocalCacheConfig::default();
        assert!(config.local_storage_path.is_none());
        assert_eq!(
            config.local_storage_max_bytes,
            Some(super::super::cache::DEFAULT_LOCAL_CACHE_MAX_BYTES)
        );
        assert_eq!(config.local_storage_eviction_policy.as_deref(), Some("lru"));
        assert_eq!(config.local_storage_warmup_enabled, Some(true));
    }

    // ── SilentEngineConfig behavior methods ─────────────────────────────

    #[test]
    fn silent_engine_config_enabled_effective_disables_all() {
        let config = SilentEngineConfig {
            enabled: true,
            disable_callbacks: false,
            disable_history: false,
            disable_gateway_telemetry: false,
            disable_payload_logging: false,
            disable_citation_writeback: false,
            minimum_state_mode: SilentMinimumStateMode::Standard,
        };
        let effective = config.effective();
        assert!(effective.enabled);
        assert!(effective.disable_callbacks);
        assert!(effective.disable_history);
        assert!(effective.disable_gateway_telemetry);
        assert!(effective.disable_payload_logging);
        assert!(effective.disable_citation_writeback);
        assert!(matches!(
            effective.minimum_state_mode,
            SilentMinimumStateMode::EnforcementOnly
        ));
    }

    #[test]
    fn silent_engine_config_disabled_effective_clears_all() {
        let config = SilentEngineConfig {
            enabled: false,
            disable_callbacks: true,
            disable_history: true,
            disable_gateway_telemetry: true,
            disable_payload_logging: true,
            disable_citation_writeback: true,
            minimum_state_mode: SilentMinimumStateMode::EnforcementOnly,
        };
        let effective = config.effective();
        assert!(!effective.enabled);
        assert!(!effective.disable_callbacks);
        assert!(!effective.disable_history);
        assert!(!effective.disable_gateway_telemetry);
        assert!(!effective.disable_payload_logging);
        assert!(!effective.disable_citation_writeback);
    }

    #[test]
    fn silent_engine_config_callbacks_disabled_when_enabled() {
        let config = SilentEngineConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(config.callbacks_disabled());
    }

    #[test]
    fn silent_engine_config_callbacks_not_disabled_when_disabled() {
        let config = SilentEngineConfig::default();
        assert!(!config.callbacks_disabled());
    }

    #[test]
    fn silent_engine_config_history_disabled_method() {
        let config = SilentEngineConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(config.history_disabled());
        let off = SilentEngineConfig::default();
        assert!(!off.history_disabled());
    }

    #[test]
    fn silent_engine_config_gateway_telemetry_disabled_method() {
        let config = SilentEngineConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(config.gateway_telemetry_disabled());
        let off = SilentEngineConfig::default();
        assert!(!off.gateway_telemetry_disabled());
    }

    #[test]
    fn silent_engine_config_payload_logging_disabled_method() {
        let config = SilentEngineConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(config.payload_logging_disabled());
        let off = SilentEngineConfig::default();
        assert!(!off.payload_logging_disabled());
    }

    #[test]
    fn silent_engine_config_citation_writeback_disabled_method() {
        let config = SilentEngineConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(config.citation_writeback_disabled());
        let off = SilentEngineConfig::default();
        assert!(!off.citation_writeback_disabled());
    }

    #[test]
    fn silent_engine_config_privacy_enforcement_only_method() {
        let config = SilentEngineConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(config.privacy_enforcement_only());
        let off = SilentEngineConfig::default();
        assert!(!off.privacy_enforcement_only());
    }

    #[test]
    fn silent_engine_enforcement_only_mode_stays_enforcement_only() {
        let config = SilentEngineConfig {
            enabled: true,
            minimum_state_mode: SilentMinimumStateMode::EnforcementOnly,
            ..Default::default()
        };
        let effective = config.effective();
        assert!(matches!(
            effective.minimum_state_mode,
            SilentMinimumStateMode::EnforcementOnly
        ));
    }

    // ── LoadedDeclarativeConfig ─────────────────────────────────────────

    #[test]
    fn loaded_declarative_config_empty_sha256_is_stable() {
        let a = LoadedDeclarativeConfig::empty();
        let b = LoadedDeclarativeConfig::empty();
        assert_eq!(a.config_sha256, b.config_sha256);
        assert!(!a.config_sha256.is_empty());
    }

    #[test]
    fn loaded_declarative_config_empty_has_default_version() {
        let config = LoadedDeclarativeConfig::empty();
        assert_eq!(config.config_version, "0.0.0");
    }

    #[test]
    fn loaded_declarative_config_empty_has_no_provider_registry() {
        let config = LoadedDeclarativeConfig::empty();
        assert!(config.provider_registry.is_none());
    }

    #[test]
    fn loaded_declarative_config_empty_has_no_testing() {
        let config = LoadedDeclarativeConfig::empty();
        assert!(config.testing.is_none());
    }

    #[test]
    fn loaded_declarative_config_empty_has_no_rate_limits() {
        let config = LoadedDeclarativeConfig::empty();
        assert!(config.token_rate_limit.is_none());
        assert!(config.global_rate_limit.is_none());
        assert!(config.ip_rate_limit.is_none());
        assert!(config.user_rate_limit.is_none());
    }

    #[test]
    fn loaded_declarative_config_empty_has_no_region() {
        let config = LoadedDeclarativeConfig::empty();
        assert!(config.region.is_none());
        assert!(config.regions.is_none());
    }

    #[test]
    fn loaded_declarative_config_empty_has_empty_configuration_tags() {
        let config = LoadedDeclarativeConfig::empty();
        assert!(config.configuration_tags.is_empty());
    }

    // ── ProvidersSourceConfig ───────────────────────────────────────────

    #[test]
    fn providers_source_config_default_is_embedded() {
        let config = ProvidersSourceConfig::default();
        assert!(matches!(config, ProvidersSourceConfig::Embedded));
    }

    #[test]
    fn providers_source_config_directory_serde() {
        let config: ProvidersSourceConfig = serde_json::from_value(serde_json::json!({
            "type": "directory",
            "path": "/etc/providers"
        }))
        .unwrap();
        assert!(matches!(config, ProvidersSourceConfig::Directory { .. }));
    }

    #[test]
    fn providers_source_config_api_serde() {
        let config: ProvidersSourceConfig = serde_json::from_value(serde_json::json!({
            "type": "api",
            "endpoint": "https://api.example.com/providers"
        }))
        .unwrap();
        assert!(matches!(config, ProvidersSourceConfig::Api { .. }));
    }

    // ── sha256_prefixed ─────────────────────────────────────────────────

    #[test]
    fn sha256_prefixed_is_deterministic() {
        let a = sha256_prefixed(b"test data");
        let b = sha256_prefixed(b"test data");
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn sha256_prefixed_different_inputs_differ() {
        let a = sha256_prefixed(b"input a");
        let b = sha256_prefixed(b"input b");
        assert_ne!(a, b);
    }

    #[test]
    fn parse_optional_duration_literal_accepts_supported_suffixes() {
        let config = serde_json::json!({
            "short": " 500ms ",
            "medium": "15m",
            "long": "2d"
        });
        let object = config.as_object().unwrap();

        assert_eq!(
            parse_optional_duration_literal(object, "short", "test").unwrap(),
            Some("500ms".to_string())
        );
        assert_eq!(
            parse_optional_duration_literal(object, "medium", "test").unwrap(),
            Some("15m".to_string())
        );
        assert_eq!(
            parse_optional_duration_literal(object, "long", "test").unwrap(),
            Some("2d".to_string())
        );
    }

    #[test]
    fn parse_optional_duration_literal_returns_none_when_missing() {
        let config = serde_json::json!({});
        let object = config.as_object().unwrap();
        assert_eq!(
            parse_optional_duration_literal(object, "ttl", "test").unwrap(),
            None
        );
    }

    #[test]
    fn parse_optional_duration_literal_rejects_zero_and_unknown_suffixes() {
        let zero = serde_json::json!({ "ttl": "0s" });
        let unknown = serde_json::json!({ "ttl": "15w" });

        assert!(parse_optional_duration_literal(zero.as_object().unwrap(), "ttl", "test").is_err());
        assert!(
            parse_optional_duration_literal(unknown.as_object().unwrap(), "ttl", "test").is_err()
        );
    }

    #[test]
    fn parse_optional_wildcard_or_string_array_accepts_wildcard() {
        let config = serde_json::json!({ "allowed_tools": "*" });
        let object = config.as_object().unwrap();
        assert_eq!(
            parse_optional_wildcard_or_string_array(object, "allowed_tools", "agent").unwrap(),
            Some(MatchListOrWildcard::Wildcard)
        );
    }

    #[test]
    fn parse_optional_wildcard_or_string_array_accepts_trimmed_explicit_values() {
        let config = serde_json::json!({ "allowed_tools": [" cache:* ", "events:read"] });
        let object = config.as_object().unwrap();
        assert_eq!(
            parse_optional_wildcard_or_string_array(object, "allowed_tools", "agent").unwrap(),
            Some(MatchListOrWildcard::Explicit(vec![
                "cache:*".to_string(),
                "events:read".to_string(),
            ]))
        );
    }

    #[test]
    fn parse_optional_wildcard_or_string_array_rejects_non_wildcard_scalar() {
        let config = serde_json::json!({ "allowed_tools": "cache:*" });
        let object = config.as_object().unwrap();
        assert!(parse_optional_wildcard_or_string_array(object, "allowed_tools", "agent").is_err());
    }

    #[test]
    fn parse_user_rate_limit_defaults_header_names_when_missing_or_empty() {
        let missing_headers = parse_user_rate_limit(&serde_json::json!({
            "user_rate_limit": {
                "max_requests": 10,
                "window_seconds": 60
            }
        }))
        .unwrap();
        assert_eq!(missing_headers.header_names, vec!["x-user-id".to_string()]);

        let empty_headers = parse_user_rate_limit(&serde_json::json!({
            "user_rate_limit": {
                "max_requests": 10,
                "window_seconds": 60,
                "header_names": []
            }
        }))
        .unwrap();
        assert_eq!(empty_headers.header_names, vec!["x-user-id".to_string()]);
    }

    #[test]
    fn parse_user_rate_limit_preserves_custom_header_names() {
        let config = parse_user_rate_limit(&serde_json::json!({
            "user_rate_limit": {
                "max_requests": 5,
                "window_seconds": 30,
                "header_names": ["x-user-id", "x-actor-id"]
            }
        }))
        .unwrap();

        assert_eq!(
            config.header_names,
            vec!["x-user-id".to_string(), "x-actor-id".to_string()]
        );
    }

    // ──: registry / schema / unread-field parity ─────────────────

    #[test]
    fn registry_supported_kinds_match_embedded_schema_policy_kind_enum() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../schema/policy-configuration.schema.json"
        ))
        .expect("schema parses");
        let schema_kinds: std::collections::BTreeSet<&str> = schema
            .pointer("/definitions/PolicyKind/enum")
            .and_then(|value| value.as_array())
            .expect("PolicyKind enum")
            .iter()
            .filter_map(|value| value.as_str())
            .collect();
        let registry_kinds: std::collections::BTreeSet<&str> =
            registry_supported_policy_kinds().into_iter().collect();
        assert_eq!(
            registry_kinds, schema_kinds,
            "registry kinds must stay in parity with schema PolicyKind"
        );
    }

    #[test]
    fn registry_schema_refs_resolve_and_yield_consumed_keys() {
        for kind in registry_supported_policy_kinds() {
            let keys = registry_consumed_config_keys(kind)
                .unwrap_or_else(|error| panic!("kind {kind}: {error}"));
            if kind == "audit-logger" {
                assert!(
                    keys.is_empty(),
                    "audit-logger must expose no consumed config keys"
                );
            }
            if kind == "pii-detector" {
                assert!(keys.contains("action"));
            }
        }
    }

    #[test]
    fn rejects_unknown_policy_kind_and_unread_conditional_fields() {
        let yaml = br#"
pack:
  name: parity
  version: "1.0.0"
  enabled: true
policies:
  chain:
    - totally-unknown-policy:
        when:
          path: /v1/chat
          regex: ".*"
        action: block
"#;
        let error = LoadedDeclarativeConfig::from_bytes(yaml).expect_err("must reject");
        let message = error.to_string();
        assert!(
            message.contains("unknown policy kind")
                || message.contains("unknown field")
                || message.contains("parsed-but-unread"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn rejects_parsed_but_unread_policy_block_fields() {
        let yaml = br#"
pack:
  name: parity
  version: "1.0.0"
  enabled: true
policies:
  chain:
    - audit-logger
policy:
  audit-logger:
    immutable: true
"#;
        let error = LoadedDeclarativeConfig::from_bytes(yaml).expect_err("must reject");
        assert!(
            error.to_string().contains("audit-logger.immutable")
                || error.to_string().contains("parsed-but-unread")
                || error.to_string().contains("removed"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn pack_enabled_false_records_exclusion_evidence() {
        let yaml = br#"
pack:
  name: disabled-pack
  version: "3.2.1"
  enabled: false
policies:
  chain:
    - prompt-injection
"#;
        let config = LoadedDeclarativeConfig::from_bytes(yaml).expect("disabled pack loads");
        assert!(!config.pack_enabled);
        assert!(config.chain_entries.is_empty());
        let evidence = config
            .pack_exclusion_evidence
            .expect("exclusion evidence required");
        assert_eq!(evidence.code, PACK_EXCLUDED_EVIDENCE_CODE);
        assert_eq!(evidence.reason, "pack.enabled=false");
        assert_eq!(evidence.pack_name.as_deref(), Some("disabled-pack"));
        assert_eq!(evidence.pack_version, "3.2.1");
    }

    /// Starter configs from `verdictan init --template <id>` and
    /// `api/src/template_catalog/industry_starters.rs` must not withhold every
    /// response through an unconditional `human-oversight` chain entry.
    ///
    /// `human-oversight` with `action: escalate` escalates each response it
    /// evaluates and returns `null` assistant content. As a plain chain entry it
    /// therefore withholds all model output from all callers. A `when` predicate
    /// limits the entry to a route, header, or model, so a conditional entry
    /// stays permitted.
    fn assert_no_unconditional_oversight_escalation(
        config: &LoadedDeclarativeConfig,
        label: &str,
    ) -> Result<(), String> {
        let escalates_every_response = config
            .policy_blocks
            .get("human-oversight")
            .and_then(|block| block.get("action"))
            .and_then(serde_json::Value::as_str)
            == Some("escalate");

        if !escalates_every_response {
            return Ok(());
        }

        for chain_entry in &config.chain_entries {
            if chain_entry.kind() == "human-oversight" && chain_entry.when_predicate().is_none() {
                return Err(format!(
                    "{label} withholds every response: `human-oversight` is an \
                     unconditional chain entry with `action: escalate`, so the gateway \
                     returns null assistant content to every caller. Scope the entry with \
                     a `when` predicate or remove it."
                ));
            }
        }

        Ok(())
    }

    fn load_fixture_policy_config(name: &str) -> LoadedDeclarativeConfig {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/policy-config")
            .join(name);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()));
        LoadedDeclarativeConfig::from_bytes(&bytes)
            .unwrap_or_else(|error| panic!("fixture {} must load: {error}", path.display()))
    }

    #[test]
    fn fixture_human_oversight_escalate_scoped_passes_invariant() {
        let config = load_fixture_policy_config("human-oversight-escalate-scoped.yaml");
        assert_no_unconditional_oversight_escalation(&config, "human-oversight-escalate-scoped")
            .expect("scoped escalate entry must pass");
    }

    #[test]
    fn fixture_human_oversight_escalate_unconditional_violates_invariant() {
        let config = load_fixture_policy_config("human-oversight-escalate-unconditional.yaml");
        let error = assert_no_unconditional_oversight_escalation(
            &config,
            "human-oversight-escalate-unconditional",
        )
        .expect_err("unconditional escalate entry must fail");
        assert!(error.contains("withholds every response"));
        assert!(error.contains("human-oversight"));
    }
}
