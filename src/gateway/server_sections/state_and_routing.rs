// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Server section module.
//! Child of `gateway::server`; parent private items remain visible via `use crate::gateway::*`.
// Parent `server.rs` still owns private routing types; this module re-exports
// `pub(crate)` helpers that take those types until ownership is fully moved.
#![allow(private_interfaces)]
use super::*;

pub struct ActiveGatewayStateView<'a> {
    pub gateway_id: Option<Arc<str>>,
    pub upstream_base: &'a str,
    pub upstream_auth: &'a Option<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    pub fail_mode: FailMode,
    pub client: &'a reqwest::Client,
    pub event_sink: &'a Option<EventSink>,
    pub agent_context_service: Option<Arc<crate::gateway::agent_context::AgentContextService>>,
    pub task_novelty_service: Option<Arc<crate::gateway::task_novelty::TaskNoveltyService>>,
    pub history_service: Option<Arc<crate::gateway::history::HistoryService>>,
    pub hosted_gateway_local_access:
        Option<crate::gateway::declarative_config::HostedGatewayLocalAccessConfig>,
    pub config_name: Option<String>,
    pub config_sha256: String,
    pub config_version: String,
    /// Plain-string view of the policy chain.
    /// Used by streaming helpers, output-phase loop, and chain_has_* checks.
    pub policy_chain: Vec<String>,
    /// Typed chain entries for predicate-aware input-phase evaluation (Phase 10).
    pub chain_entries: Vec<crate::gateway::enforcement::ChainEntry>,
    pub policy_blocks: crate::gateway::PolicyBlocks,
    /// Route configuration for path-based chain and upstream overrides (Phase 16/17).
    pub route_config: crate::gateway::routes::RouteConfig,
    pub models_endpoint: crate::gateway::models_endpoint::ModelsEndpointConfig,
    pub moderation: Option<crate::gateway::declarative_config::ModerationConfig>,
    pub rate_limiter: &'a Arc<crate::gateway::rate_limit::AdaptiveConcurrencyLimiter>,
    pub provider_cache: &'a Arc<crate::gateway::cache::ProviderResponseCache>,
    pub provider_registry: Option<crate::gateway::providers::ProviderRegistry>,
    pub catalog_snapshot: crate::gateway::provider_catalog::CatalogSnapshot,
    pub provider_metrics: &'a Arc<crate::gateway::provider_metrics::ProviderMetrics>,
    /// Phase 19 — global request-count rate limiter (optional).
    pub global_rate_limiter: Option<Arc<crate::gateway::rate_limit::GlobalRateLimiter>>,
    /// Phase 19 — per-client-IP rate limiter (optional).
    pub ip_rate_limiter: Option<Arc<crate::gateway::rate_limit::IpRateLimiter>>,
    /// Phase 18 — token-consumption rate limiter (optional).
    pub token_rate_limiter: Option<Arc<crate::gateway::token_rate_limit::TokenRateLimiter>>,
    /// Per-user request-count rate limiter (optional).
    pub user_rate_limiter: Option<Arc<crate::gateway::rate_limit::UserRateLimiter>>,
    /// Per-token RPM limiter (always present).
    pub key_rate_limiter: &'a Arc<crate::gateway::rate_limit::TokenRateLimiter>,
    /// Legacy local request-count telemetry state.
    pub key_request_tracker: &'a Arc<crate::gateway::token_rate_limit::TokenRequestTracker>,
    /// Local post-dispatch spend telemetry; never an admission authority.
    pub key_budget_tracker: &'a Arc<crate::gateway::token_rate_limit::TokenBudgetTracker>,
    /// Phase 20 — request size limit middleware (optional).
    pub size_limit: Option<Arc<crate::gateway::size_limit::SizeLimitMiddleware>>,
    /// Phase 21 — consumer-group config and in-memory request limiter (optional).
    pub consumer_groups: Option<crate::gateway::consumer::ConsumerGroupConfig>,
    /// Phase 35 — provider-specific additional auth/protocol headers.
    pub provider_extra_headers: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    pub semantic_cache: Option<crate::gateway::cache::SemanticCacheConfig>,
    pub workflow_cache: Option<crate::gateway::declarative_config::WorkflowCacheRuntimeConfig>,
    pub ip_allowlist: Option<Arc<Vec<ipnet::IpNet>>>,
    pub ip_allowlist_trusted_proxies: Arc<Vec<ipnet::IpNet>>,
    pub region_key: Option<String>,
    /// When `true` the gateway is in connected mode.
    pub connected_mode: bool,
    pub managed_public_endpoint_host: Option<String>,
    pub requested_region_group: Option<String>,
    pub current_publication: Option<crate::runtime::ConnectedGatewayPublicationDescriptor>,
    pub(crate) runtime_routing_settings: RuntimeRoutingSettings,
    pub(crate) runtime_cache_ttl_override: Option<Duration>,
    pub(crate) runtime_allow_fallbacks: bool,
    pub(crate) runtime_privacy_restricted: bool,
    pub(crate) shadow_routing: EffectiveShadowRouting,
    /// Auto virtual provider config.
    pub auto_provider: crate::gateway::auto_provider::AutoProviderConfig,
    pub history_config: Option<crate::gateway::declarative_config::HistoryRuntimeConfig>,
    pub gateway_context_fabric: Option<crate::gateway::declarative_config::ContextFabricConfig>,
    pub mcp_server_config: Option<crate::gateway::declarative_config::McpServerConfig>,
    pub agent_declarations: Vec<crate::gateway::declarative_config::GatewayAgentDeclaration>,
    pub silent_engine: Option<crate::gateway::declarative_config::SilentEngineConfig>,
    pub agents_runtime: Option<crate::gateway::declarative_config::AgentsRuntimeConfig>,
    /// Per-target HTTP request timeout. `None` means no timeout is applied.
    /// Set from `ProviderTarget::effective_timeout` when routing through a registry.
    pub request_timeout: Option<std::time::Duration>,
    pub(crate) stream_response_adapter: Option<StreamingResponseAdapter>,
    pub allow_insecure_tls: bool,
    /// The provider target ID selected during routing (used for agent_id correlation).
    pub current_target_id: Option<String>,
    /// The registered agent UUID associated with the governed request, if resolved.
    pub current_agent_id: Option<String>,
    // Outcome A: when set, provider ordering is restricted to this
    /// single target id so reserve/dispatch/commit cannot fall back to another
    /// provider than the one reserved against.
    pub ua_pinned_target_id: Option<String>,
    // Outcome A: evaluate document accepted for the current request.
    pub ua_eval_document: Option<crate::gateway::usage_authorization::UsageAuthorizationDocument>,
    // Outcome A: financial reservation id from `ua_authorize`.
    pub ua_authorization_id: Option<String>,
    // Outcome A: dispatch attempt id for the current reservation.
    // Outcome A: whether `ua_dispatch` succeeded for this request.
    pub ua_dispatch_acquired: bool,
    // increment 3c: provider-target ids the subject is NOT allowed to
    /// use, decided by a READ-ONLY usage-authorization evaluate per routing candidate
    /// (`populate_ua_denied_target_ids`). `score_targets`/auto-routing exclude
    /// these. Empty for every non-UA / legacy path, so selection is byte-identical.
    pub ua_denied_target_ids: std::collections::HashSet<String>,
    pub api_token_present: bool,
    pub request_finops: Option<RequestFinopsContext>,
    /// Phase 25 — centralized distributed state reference.
    pub distributed_state: Option<&'a Arc<crate::gateway::distributed_state::DistributedState>>,
    /// Phase 25 — distributed rate limit params: (limit, window_secs).
    /// Derived from `global_rate_limit` config when a distributed backend is configured.
    pub distributed_rl_params: Option<(u64, u64)>,
    /// Session identifier extracted from x-session-id header or request metadata.
    pub session_id: Option<String>,
    /// Connected-mode: configuration UUID from the resolved org config.
    pub configuration_id: Option<Arc<str>>,
    /// Connected-mode: configuration version UUID from the resolved org config.
    pub configuration_version_id: Option<Arc<str>>,
    pub token_validation_cache: &'a Arc<
        crate::gateway::token_validation_cache::TokenValidationCache<TokenValidationResponse>,
    >,
    pub gateway_runtime_metrics: &'a Arc<GatewayRuntimeMetrics>,
    pub rollout_grade: bool,
    pub rollout_grade_required: bool,
}
pub(crate) const GITHUB_MODELS_DEFAULT_API_VERSION: &str = "2026-03-10";
pub(crate) const GITHUB_MODELS_HOSTS: &[&str] =
    &["models.github.ai", "models.inference.ai.azure.com"];

pub(crate) fn build_agent_context_service(
    event_sink: &Option<EventSink>,
) -> Option<Arc<crate::gateway::agent_context::AgentContextService>> {
    event_sink.as_ref().map(|sink| {
        Arc::new(crate::gateway::agent_context::AgentContextService::new(
            sink.client.clone(),
            sink.machine_client().ok().cloned(),
            sink.base_url.clone(),
            2_000,
        ))
    })
}

pub(crate) fn build_task_novelty_service(
    event_sink: &Option<EventSink>,
) -> Option<Arc<crate::gateway::task_novelty::TaskNoveltyService>> {
    event_sink.as_ref().map(|sink| {
        Arc::new(crate::gateway::task_novelty::TaskNoveltyService::new(
            sink.client.clone(),
            sink.machine_client().ok().cloned(),
            sink.base_url.clone(),
            1_500,
        ))
    })
}

pub(crate) fn build_history_service(
    event_sink: &Option<EventSink>,
    loaded_config: &LoadedDeclarativeConfig,
) -> Option<Arc<crate::gateway::history::HistoryService>> {
    if loaded_config
        .resolved_silent_engine_config()
        .is_some_and(|config| config.history_disabled())
    {
        return None;
    }
    let cfg = loaded_config.resolved_history_config().unwrap_or_else(|| {
        // Default: enable history capture when connected to the control-plane
        // API so that gateway decisions appear in console History even when no
        // explicit policy config is mounted.
        crate::gateway::declarative_config::HistoryRuntimeConfig {
            enabled: event_sink.is_some(),
            mode: "metadata_only".to_string(),
            include_blocked: false,
        }
    });
    if !cfg.enabled {
        return None;
    }
    let sink = event_sink.as_ref()?;
    Some(Arc::new(crate::gateway::history::HistoryService::new(
        sink.client.clone(),
        sink.machine_client().ok().cloned(),
        sink.base_url.clone(),
        cfg,
    )))
}

impl<'a> ActiveGatewayStateView<'a> {
    pub fn from_state(state: &'a GatewayState, config: LoadedDeclarativeConfig) -> Self {
        let connected_read_model = state.connected_read_model.snapshot();
        // Derive distributed rate limit params before config fields are moved.
        let distributed_rl_params = config.distributed_rate_limit.as_ref().and_then(|_| {
            config
                .global_rate_limit
                .as_ref()
                .map(|rl| (rl.max_requests, rl.window_seconds))
        });
        let history_config = config.resolved_history_config();
        let silent_engine = config
            .resolved_silent_engine_config()
            .map(|value| value.effective());
        let declarative_routing = config.resolved_runtime_routing_config();
        let agent_context_service = build_agent_context_service(&state.event_sink);
        let task_novelty_service = build_task_novelty_service(&state.event_sink);
        let history_service = build_history_service(&state.event_sink, &config);
        let hosted_gateway_local_access = config
            .hosted_gateway
            .as_ref()
            .map(|runtime| runtime.local_access.clone());
        Self {
            gateway_id: state.gateway_id.clone(),
            upstream_base: &state.upstream_base,
            upstream_auth: &state.upstream_auth,
            fail_mode: state.fail_mode,
            client: &state.client,
            event_sink: &state.event_sink,
            agent_context_service,
            task_novelty_service,
            history_service,
            hosted_gateway_local_access,
            config_name: config.pack_name,
            config_sha256: config.config_sha256,
            config_version: config.config_version,
            policy_chain: config
                .chain_entries
                .iter()
                .map(|e| e.kind().to_string())
                .collect(),
            chain_entries: config.chain_entries,
            policy_blocks: config.policy_blocks,
            route_config: config.route_config,
            models_endpoint: config.models_endpoint,
            moderation: config.moderation,
            rate_limiter: &state.rate_limiter,
            provider_cache: &state.provider_cache,
            provider_registry: config.provider_registry,
            catalog_snapshot: state.catalog_resolver.cached_snapshot(),
            provider_metrics: &state.provider_metrics,
            global_rate_limiter: state.global_rate_limiter.clone(),
            ip_rate_limiter: state.ip_rate_limiter.clone(),
            user_rate_limiter: state.user_rate_limiter.clone(),
            token_rate_limiter: state.token_rate_limiter.clone(),
            size_limit: state.size_limit.clone(),
            consumer_groups: config.consumer_groups,
            provider_extra_headers: Vec::new(),
            semantic_cache: config.semantic_cache,
            workflow_cache: config.workflow_cache,
            ip_allowlist: state.ip_allowlist.clone(),
            ip_allowlist_trusted_proxies: state.ip_allowlist_trusted_proxies.clone(),
            region_key: connected_read_model.region_key,
            connected_mode: state.connected_mode,
            managed_public_endpoint_host: None,
            requested_region_group: None,
            current_publication: None,
            runtime_routing_settings: runtime_routing_from_declarative(declarative_routing),
            runtime_cache_ttl_override: None,
            runtime_allow_fallbacks: true,
            runtime_privacy_restricted: false,
            shadow_routing: EffectiveShadowRouting::default(),
            auto_provider: config.auto_provider,
            history_config,
            gateway_context_fabric: config.context_fabric,
            mcp_server_config: config.mcp_server,
            agent_declarations: config.agents,
            silent_engine,
            agents_runtime: config.agents_runtime,
            request_timeout: None,
            stream_response_adapter: None,
            allow_insecure_tls: false,
            current_target_id: None,
            current_agent_id: None,
            ua_pinned_target_id: None,
            ua_eval_document: None,
            ua_authorization_id: None,
            ua_dispatch_acquired: false,
            ua_denied_target_ids: std::collections::HashSet::new(),
            api_token_present: false,
            request_finops: None,
            distributed_state: state.distributed_state.as_ref(),
            distributed_rl_params,
            session_id: None,
            configuration_id: None,
            configuration_version_id: None,
            token_validation_cache: &state.token_validation_cache,
            gateway_runtime_metrics: &state.gateway_runtime_metrics,
            rollout_grade: state.rollout_grade,
            rollout_grade_required: state.rollout_grade_required,
            key_rate_limiter: &state.key_rate_limiter,
            key_request_tracker: &state.key_request_tracker,
            key_budget_tracker: &state.key_budget_tracker,
        }
    }

    pub fn registered_agent_id(&self) -> Option<&str> {
        self.current_agent_id.as_deref()
    }

    pub fn apply_agent_overrides(&mut self) {
        let agent_id = match self.current_agent_id.as_deref() {
            Some(id) => id,
            None => return,
        };
        let overrides = match self.agents_runtime.as_ref() {
            Some(runtime) => &runtime.overrides,
            None => return,
        };
        let agent_override = match overrides.iter().find(|o| o.agent_id == agent_id) {
            Some(o) => o,
            None => return,
        };

        if let Some(ref routing) = agent_override.runtime_routing {
            self.runtime_routing_settings = runtime_routing_from_declarative(Some(routing.clone()));
            self.runtime_allow_fallbacks = routing.default_provider_policy.allow_fallbacks;
            self.runtime_privacy_restricted = routing.default_provider_policy.zdr
                || routing
                    .default_provider_policy
                    .data_collection
                    .eq_ignore_ascii_case("deny");
            self.shadow_routing = EffectiveShadowRouting {
                enabled: routing.shadow_routing.enabled,
                capture_mode: routing.shadow_routing.capture_mode.clone(),
            };
        }

        if let Some(ref plugin_gov) = agent_override.plugin_governance {
            self.runtime_routing_settings.plugin_governance = RuntimePluginGovernance {
                defaults: plugin_gov
                    .defaults
                    .iter()
                    .map(|p| RuntimePluginSetting {
                        id: p.id.clone(),
                        enabled: p.enabled,
                        options: p.options.clone(),
                    })
                    .collect(),
                forced_on: plugin_gov
                    .forced_on
                    .iter()
                    .map(|p| RuntimePluginSetting {
                        id: p.id.clone(),
                        enabled: p.enabled,
                        options: p.options.clone(),
                    })
                    .collect(),
                prevent_overrides: plugin_gov.prevent_overrides.clone(),
            };
        }

        if let Some(ref se) = agent_override.silent_engine {
            self.silent_engine = Some(se.effective());
        }
    }
}

/// Parse caller-supplied `X-Verdictan-Team` values.
///
/// Connected / authenticated gateways must not treat this as authoritative.
/// Use [`resolve_request_team_slugs`] for policy-chain targeting.
pub fn extract_request_team_slugs(headers: &HeaderMap) -> Vec<String> {
    parse_csv_header_values_for_teams(headers, "x-verdictan-team")
}

pub(crate) fn parse_csv_header_values_for_teams(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Team selectors for policy-chain targeting.
///
/// Precedence:
/// 1. Authenticated `RequestFinopsContext.selected_team_ids` (API-issued memberships projected during token validation; not caller headers).
/// 2. Authenticated identity team memberships / `team_id`.
/// 3. Authoritative identity with an empty team set → org-wide (empty selectors); caller `X-Verdictan-Team` is ignored.
/// 4. Explicit local unauthenticated profile (`allow_local_header_selector`) → optional header selector for local gateways only.
/// 5. Connected or otherwise non-local profiles → strip/ignore the header.
pub fn resolve_request_team_slugs(
    headers: &HeaderMap,
    finops: Option<&RequestFinopsContext>,
    allow_local_header_selector: bool,
) -> Vec<String> {
    if let Some(ctx) = finops {
        if !ctx.selected_team_ids.is_empty() {
            return ctx.selected_team_ids.clone();
        }
        if let Some(identity) = ctx.authenticated_identity.as_ref() {
            if !identity.team_ids().is_empty() {
                return identity.team_ids().to_vec();
            }
        }
        if let Some(team_id) = ctx
            .team_id
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            return vec![team_id.to_string()];
        }
        // Authoritative identity with an empty team set means org-wide context;
        // do not honor caller-supplied reserved team headers.
        if ctx.authenticated_identity.is_some() || ctx.has_authoritative_identity() {
            return Vec::new();
        }
    }

    if allow_local_header_selector {
        return extract_request_team_slugs(headers);
    }

    // Connected / non-local profile: strip caller team headers from chain selection.
    Vec::new()
}

pub(crate) fn initial_public_route_config(state: &GatewayState) -> LoadedDeclarativeConfig {
    state.active_config.snapshot()
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct GatewayMcpRouteSettings {
    pub(crate) enabled: bool,
    pub(crate) max_request_body_bytes: usize,
}

pub(crate) const DEFAULT_MCP_MAX_PROMPT_BYTES: u64 = 100_000;
pub(crate) const DEFAULT_MCP_MAX_CONCURRENT_SESSIONS: u32 = 10;

pub(crate) fn gateway_mcp_route_settings(state: &GatewayState) -> GatewayMcpRouteSettings {
    let config = initial_public_route_config(state);
    let Some(mcp_server) = config.mcp_server else {
        return GatewayMcpRouteSettings {
            enabled: false,
            max_request_body_bytes: 262_144,
        };
    };

    let path_enabled = mcp_server
        .path
        .as_deref()
        .map(|path| path == "/mcp")
        .unwrap_or(true);
    let max_request_body_bytes = mcp_server
        .max_request_body_bytes
        .unwrap_or(262_144)
        .min(usize::MAX as u64) as usize;

    GatewayMcpRouteSettings {
        enabled: mcp_server.enabled.unwrap_or(true) && path_enabled,
        max_request_body_bytes,
    }
}

pub(crate) fn published_mcp_action_bridge(
    config: &LoadedDeclarativeConfig,
) -> crate::gateway::runtimes::network::mcp::McpBridgeConfig {
    use crate::gateway::runtimes::network::mcp::{McpBridgeConfig, McpContainmentConfig};
    use crate::gateway::tool_budget::{ToolBudgetConfig, ToolBudgetLimit};
    use crate::gateway::tool_security::{AnalysisMode, ToolSecurityConfig};
    use crate::gateway::tool_validation::{SemanticValidationConfig, ToolValidationConfig};

    let tool_validation = config
        .tool_validation
        .as_ref()
        .map(|decl| ToolValidationConfig {
            declared_tools: decl.declared_tools.clone(),
            allow_undeclared: decl.allow_undeclared,
            schemas: Default::default(),
            semantic_validation: SemanticValidationConfig {
                enabled: decl.semantic_validation_enabled,
                endpoint: decl.semantic_validation_endpoint.clone(),
                ..Default::default()
            },
        });

    let tool_security = config.tool_security.as_ref().map(|decl| {
        let analysis_mode = match decl.analysis_mode.trim().to_ascii_lowercase().as_str() {
            "external" => AnalysisMode::External,
            _ => AnalysisMode::Local,
        };
        ToolSecurityConfig {
            analysis_mode,
            firewall_endpoint: decl.firewall_endpoint.clone(),
            secret_key_env: None,
            fail_closed: decl.fail_closed,
            blocked_entity_types: decl.blocked_entity_types.clone(),
            blocked_patterns: decl.blocked_patterns.clone(),
        }
    });

    let tool_budget = config.tool_budget.as_ref().map(|decl| {
        let mut budgets = std::collections::HashMap::new();
        for (name, limit) in &decl.budgets {
            budgets.insert(
                name.clone(),
                ToolBudgetLimit {
                    max_tokens: limit.max_tokens,
                    max_calls: limit.max_calls,
                },
            );
        }
        ToolBudgetConfig { budgets }
    });

    // Prefer the first declared tool-server containment contract when present so
    // those fields are enforced on published `/mcp` dispatch rather than unread.
    let containment = config
        .tool_servers
        .first()
        .map(|server| McpContainmentConfig {
            network_policy: server.containment.network_policy.clone(),
            timeout_ms: server.containment.timeout_ms,
            max_concurrent_calls: server.containment.max_concurrent_calls,
        })
        .unwrap_or_default();

    McpBridgeConfig {
        tool_validation,
        tool_security,
        tool_budget,
        containment,
        ..Default::default()
    }
}

pub(crate) fn default_mcp_session_policy(
    config: &LoadedDeclarativeConfig,
) -> crate::mcp::server::McpSessionPolicy {
    let mcp_server = config.mcp_server.as_ref();
    let session_limits = mcp_server.and_then(|cfg| cfg.session_limits.as_ref());

    crate::mcp::server::McpSessionPolicy {
        allowed_tools: mcp_server
            .and_then(|cfg| cfg.allowed_tools.clone())
            .unwrap_or(crate::gateway::declarative_config::MatchListOrWildcard::Wildcard),
        allowed_resources: mcp_server
            .and_then(|cfg| cfg.allowed_resources.clone())
            .unwrap_or(crate::gateway::declarative_config::MatchListOrWildcard::Wildcard),
        max_prompt_bytes: session_limits
            .and_then(|cfg| cfg.max_prompt_bytes)
            .unwrap_or(DEFAULT_MCP_MAX_PROMPT_BYTES),
        max_test_inference_cost_usd: session_limits.and_then(|cfg| cfg.max_test_inference_cost_usd),
        max_concurrent_sessions: session_limits
            .and_then(|cfg| cfg.max_concurrent_sessions)
            .unwrap_or(DEFAULT_MCP_MAX_CONCURRENT_SESSIONS),
        auth_mode: mcp_server.and_then(|cfg| cfg.auth_mode.clone()),
        tool_servers: Some(crate::mcp::server::McpToolServerPolicy {
            allow_unapproved: mcp_server
                .and_then(|cfg| cfg.tool_servers.as_ref())
                .and_then(|cfg| cfg.allow_unapproved)
                .unwrap_or(false),
            allowed_ids: mcp_server
                .and_then(|cfg| cfg.tool_servers.as_ref())
                .and_then(|cfg| cfg.allowed_ids.clone())
                .unwrap_or_default(),
        }),
        action_bridge: published_mcp_action_bridge(config),
    }
}

pub(crate) fn resolve_gateway_mcp_session_policy(
    state: &GatewayState,
    state_view: &ActiveGatewayStateView<'_>,
    request_id: &str,
    traceparent: &str,
) -> Result<crate::mcp::server::McpSessionPolicy, Response<Body>> {
    let config = initial_public_route_config(state);
    let policy = if config.agents.is_empty() {
        default_mcp_session_policy(&config)
    } else {
        let bound_agent_id = resolved_request_agent_id(state_view);
        let resolved =
            crate::gateway::declarative_config::agent_config_resolution::resolve_agent_config_for_binding(
            &config,
            bound_agent_id.as_deref(),
        )
        .map_err(|error| {
            build_request_error_response(
                StatusCode::BAD_REQUEST,
                request_id,
                traceparent,
                &error.to_string(),
                "invalid_request_error",
                "mcp_agent_config_unresolved",
            )
        })?;

        if !resolved.mcp.enabled {
            return Err(build_request_error_response(
                StatusCode::FORBIDDEN,
                request_id,
                traceparent,
                "The MCP endpoint is disabled for the resolved agent configuration",
                "invalid_request_error",
                "mcp_disabled_for_agent",
            ));
        }

        crate::mcp::server::McpSessionPolicy {
            allowed_tools: resolved.mcp.allowed_tools,
            allowed_resources: resolved.mcp.allowed_resources,
            max_prompt_bytes: resolved.mcp.session_limits.max_prompt_bytes,
            max_test_inference_cost_usd: resolved.mcp.session_limits.max_test_inference_cost_usd,
            max_concurrent_sessions: resolved.mcp.session_limits.max_concurrent_sessions,
            auth_mode: resolved.mcp.auth_mode,
            tool_servers: Some(crate::mcp::server::McpToolServerPolicy {
                allow_unapproved: resolved.mcp.tool_servers.allow_unapproved,
                allowed_ids: resolved.mcp.tool_servers.allowed_ids,
            }),
            action_bridge: published_mcp_action_bridge(&config),
        }
    };

    if let Some(auth_mode) = policy.auth_mode.as_deref() {
        if !auth_mode.eq_ignore_ascii_case("bearer") {
            return Err(build_request_error_response(
                StatusCode::NOT_IMPLEMENTED,
                request_id,
                traceparent,
                "The hosted MCP endpoint currently supports only bearer auth_mode",
                "invalid_request_error",
                "mcp_auth_mode_unsupported",
            ));
        }
    }

    Ok(policy)
}

pub(crate) fn require_mcp_api_token(
    headers: &HeaderMap,
    request_id: &str,
    traceparent: &str,
) -> Result<String, Response<Body>> {
    let Some(raw_token) = extract_bearer_token(headers) else {
        return Err(build_request_error_response(
            StatusCode::UNAUTHORIZED,
            request_id,
            traceparent,
            "The MCP endpoint requires a Verdictan API token",
            "authentication_error",
            "missing_api_key",
        ));
    };

    if !is_api_token(&raw_token) {
        return Err(build_request_error_response(
            StatusCode::UNAUTHORIZED,
            request_id,
            traceparent,
            "The MCP endpoint requires a Verdictan API token",
            "authentication_error",
            "invalid_api_key",
        ));
    }

    Ok(raw_token)
}

pub(crate) fn mcp_resolved_region(state: &ActiveGatewayStateView<'_>) -> Option<String> {
    state
        .current_publication
        .as_ref()
        .and_then(|publication| publication.primary_region_group_key.clone())
        .or_else(|| state.region_key.clone())
}

pub(crate) fn require_mcp_publication_context(
    state: &ActiveGatewayStateView<'_>,
    request_id: &str,
    traceparent: &str,
) -> Result<(), Response<Body>> {
    if state.current_publication.is_some() {
        return Ok(());
    }

    Err(build_request_error_response(
        StatusCode::NOT_FOUND,
        request_id,
        traceparent,
        "The MCP endpoint is available only on published agent hostnames",
        "invalid_request_error",
        "mcp_publication_required",
    ))
}

/// Reject unpublished MCP hostnames before token validation when managed-public
/// ingress headers are absent. Ingress-admitted requests still need the full
/// public state build to resolve publication bindings.
pub(crate) fn reject_unpublished_mcp_without_ingress(
    state: &GatewayState,
    headers: &HeaderMap,
    request_id: &str,
    traceparent: &str,
) -> Option<Response<Body>> {
    if has_managed_public_ingress_headers(headers) {
        return None;
    }
    let preview = ActiveGatewayStateView::from_state(state, initial_public_route_config(state));
    require_mcp_publication_context(&preview, request_id, traceparent).err()
}

pub(crate) fn build_gateway_mcp_client(
    state: &GatewayState,
    request_state: &ActiveGatewayStateView<'_>,
    raw_token: &str,
    request_id: &str,
    traceparent: &str,
) -> Result<crate::api::AsyncApiClient, Response<Body>> {
    let Some(api_base_url) = state
        .api_base_url
        .as_deref()
        .or_else(|| state.event_sink.as_ref().map(|sink| sink.base_url()))
    else {
        return Err(build_request_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            traceparent,
            "The MCP endpoint requires control-plane API connectivity",
            "service_unavailable",
            "mcp_api_unavailable",
        ));
    };

    crate::api::AsyncApiClient::new(api_base_url, raw_token)
        .map(|client| client.with_region(mcp_resolved_region(request_state)))
        .map_err(|error| {
            tracing::error!(request_id = %request_id, error = %error, "failed to build MCP API client");
            build_request_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                traceparent,
                "The MCP endpoint could not initialize its API client",
                "service_unavailable",
                "mcp_api_unavailable",
            )
        })
}

pub(crate) fn build_gateway_mcp_trace_context(
    state: &GatewayState,
    request_state: &ActiveGatewayStateView<'_>,
    session_id: Option<&str>,
    conversation_id: Option<&str>,
    git_context: Option<crate::gateway::session::GatewayGitContext>,
    traceparent: Option<&str>,
) -> Option<crate::mcp::server::McpToolTraceContext> {
    let session_id = session_id
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let event_sink = state.event_sink.as_ref()?;
    let machine_client = event_sink.machine_client().ok()?.clone();
    let session_user_id = request_state
        .request_finops
        .as_ref()
        .and_then(|context| context.user_id.as_deref())
        .or_else(|| {
            request_state
                .request_finops
                .as_ref()
                .and_then(|context| context.created_by.as_deref())
        });
    let agent_id = request_state.current_agent_id.as_deref().or_else(|| {
        request_state
            .request_finops
            .as_ref()
            .and_then(|context| context.agent_id.as_deref())
    });
    let mut session_context = crate::gateway::session::derive_session_context_with_git_context(
        request_state
            .request_finops
            .as_ref()
            .and_then(|context| context.org_id.as_deref()),
        session_user_id,
        request_state
            .request_finops
            .as_ref()
            .and_then(|context| context.team_id.as_deref()),
        request_state
            .request_finops
            .as_ref()
            .and_then(|context| context.key_id.as_deref()),
        request_state.gateway_id.as_deref(),
        agent_id,
        conversation_id,
        request_state
            .request_finops
            .as_ref()
            .and_then(|context| context.gateway_execution_session_id.as_deref()),
        git_context,
    )?;
    session_context.session_id = session_id.to_string();

    Some(crate::mcp::server::McpToolTraceContext {
        api_base_url: event_sink.base_url().to_string(),
        machine_client,
        session_context,
        traceparent: traceparent
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
    })
}

pub(crate) async fn build_public_request_state<'a>(
    state: &'a GatewayState,
    headers: &HeaderMap,
    peer_addr: std::net::SocketAddr,
    request_id: &str,
    traceparent: &str,
) -> Result<ActiveGatewayStateView<'a>, Response<Body>> {
    let mut state_view =
        ActiveGatewayStateView::from_state(state, initial_public_route_config(state));
    let connected_read_model = state.connected_read_model.snapshot();
    state_view.api_token_present = extract_bearer_token(headers)
        .as_deref()
        .is_some_and(is_api_token);

    if state_view.connected_mode {
        state_view.request_finops = require_connected_public_auth(
            &state_view,
            headers,
            peer_addr.ip(),
            request_id,
            traceparent,
        )
        .await?;
    } else if state_view.api_token_present {
        // Hosted mode with an API token: validate and reject invalid tokens
        // when an event sink is available for key verification.
        if state_view.event_sink.is_some() {
            match resolve_request_finops_context(
                &state_view,
                headers,
                peer_addr.ip(),
                request_id,
                traceparent,
            )
            .await
            {
                Ok(Some(finops)) => {
                    state_view.request_finops = Some(finops);
                }
                Ok(None) => {}
                Err(response) => return Err(response),
            }
        }
    }

    match admit_managed_public_ingress(
        headers,
        peer_addr.ip(),
        state_view.ip_allowlist_trusted_proxies.as_ref(),
        &crate::gateway::relay::RelayTlsConfig::from_env(),
        connected_read_model.relay_hmac_secret.as_deref(),
        request_id,
        traceparent,
    )? {
        ManagedPublicIngressAdmission::Absent => {}
        ManagedPublicIngressAdmission::Admitted => {
            if let Some(response) = enforce_managed_public_endpoint_publication_binding(
                &connected_read_model,
                headers,
                request_id,
                traceparent,
            ) {
                return Err(response);
            }

            if ingress_marks_managed_public_endpoint(headers) {
                state_view.managed_public_endpoint_host = managed_public_endpoint_host(headers);
                state_view.requested_region_group =
                    managed_public_endpoint_requested_region_group(headers);
                if let Some(ref requested_host) = state_view.managed_public_endpoint_host {
                    state_view.current_publication = matched_managed_public_endpoint_publication(
                        &connected_read_model,
                        requested_host,
                        state_view.requested_region_group.as_deref(),
                    );
                }
            }
        }
    }

    if let Some(sink) = state_view.event_sink.as_ref() {
        let org_id = state_view
            .request_finops
            .as_ref()
            .and_then(|finops| finops.org_id.as_deref());
        match sink.fetch_runtime_routing_settings(org_id).await {
            Ok(settings) => {
                state_view.runtime_allow_fallbacks =
                    settings.default_provider_policy.allow_fallbacks;
                state_view.runtime_privacy_restricted = settings.default_provider_policy.zdr
                    || settings
                        .default_provider_policy
                        .data_collection
                        .eq_ignore_ascii_case("deny");
                state_view.shadow_routing = EffectiveShadowRouting {
                    enabled: settings.shadow_routing.enabled,
                    capture_mode: settings.shadow_routing.capture_mode.clone(),
                };
                state_view.runtime_routing_settings = settings;
            }
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    error = %error,
                    "runtime routing settings lookup failed; using gateway defaults"
                );
            }
        }
    }

    if silent_engine(&state_view).privacy_enforcement_only() {
        state_view.runtime_privacy_restricted = true;
        state_view.shadow_routing = EffectiveShadowRouting {
            enabled: false,
            capture_mode: "metadata_only".to_string(),
        };
    }

    if let Some(response) = enforce_request_network_controls(
        &state_view,
        headers,
        peer_addr.ip(),
        request_id,
        traceparent,
    ) {
        return Err(response);
    }

    if let Some(response) =
        enforce_distributed_request_rate_limit(&state_view, request_id, traceparent)
    {
        return Err(response);
    }

    Ok(state_view)
}

/// Managed-public ingress headers that must only be consumed from authenticated
/// proxy mTLS identities on configured trusted-proxy CIDRs.
pub(crate) const MANAGED_PUBLIC_INGRESS_HEADERS: &[&str] = &[
    "x-verdictan-public-endpoint",
    "x-verdictan-public-hostname",
    "x-verdictan-requested-region-group",
    "x-verdictan-endpoint-scope",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedPublicIngressAdmission {
    /// No managed-public ingress headers present, or they were stripped as an
    /// untrusted direct-caller spoof.
    Absent,
    /// Headers present and provenance verified (mTLS + CIDR + hostname).
    Admitted,
}

/// Remove every managed-public ingress header from `headers`.
pub(crate) fn strip_managed_public_ingress_headers(headers: &mut HeaderMap) {
    for name in MANAGED_PUBLIC_INGRESS_HEADERS {
        headers.remove(*name);
    }
}

pub(crate) fn has_managed_public_ingress_headers(headers: &HeaderMap) -> bool {
    MANAGED_PUBLIC_INGRESS_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
}

/// When `x-verdictan-public-hostname` is present it must match the request
/// `Host` after normalization. Missing public-hostname is allowed (Host
/// fallback remains available after admission).
pub(crate) fn managed_public_hostname_matches_host(headers: &HeaderMap) -> bool {
    let Some(public_host) = headers
        .get("x-verdictan-public-hostname")
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_managed_public_endpoint_host)
    else {
        return true;
    };
    let Some(request_host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_managed_public_endpoint_host)
    else {
        return false;
    };
    public_host == request_host
}

fn managed_public_ingress_reject(
    request_id: &str,
    traceparent: &str,
    message: &str,
    code: &str,
) -> Response<Body> {
    build_response(
        StatusCode::FORBIDDEN,
        HeaderValue::from_static("application/json"),
        request_id.to_string(),
        traceparent.to_string(),
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "error": error_json(message, "permission_error", code)
            }))
            .unwrap_or_else(|_| b"{}".to_vec()),
        ),
        false,
        None,
    )
}

/// Admit managed-public ingress headers only from authenticated proxy transport
/// identities on configured trusted-proxy CIDRs. Direct spoofs are treated as
/// absent (callers should strip). Partial transport/CIDR/hostname mismatches
/// reject.
pub(crate) fn admit_managed_public_ingress(
    headers: &HeaderMap,
    peer_ip: std::net::IpAddr,
    trusted_proxy_cidrs: &[ipnet::IpNet],
    tls_config: &crate::gateway::relay::RelayTlsConfig,
    relay_hmac_secret: Option<&str>,
    request_id: &str,
    traceparent: &str,
) -> Result<ManagedPublicIngressAdmission, Response<Body>> {
    if !ingress_marks_managed_public_endpoint(headers) {
        return Ok(ManagedPublicIngressAdmission::Absent);
    }

    let cidr_ok = crate::gateway::network::peer_is_trusted_proxy(peer_ip, trusted_proxy_cidrs);
    let mtls_ok = crate::gateway::relay::verify_relay_mtls(headers, tls_config);
    let relay_token_ok = crate::gateway::relay::validate_relay_token(headers, relay_hmac_secret);
    let ingress_proxy_ok =
        crate::gateway::relay::verify_ingress_proxy_mtls(headers, tls_config, relay_hmac_secret);
    let hostname_ok = managed_public_hostname_matches_host(headers);

    if cidr_ok && ingress_proxy_ok && hostname_ok {
        return Ok(ManagedPublicIngressAdmission::Admitted);
    }

    if cidr_ok || mtls_ok || relay_token_ok {
        if !cidr_ok {
            return Err(managed_public_ingress_reject(
                request_id,
                traceparent,
                "Managed public ingress rejected: peer is outside configured trusted proxy CIDRs",
                "managed_public_ingress_cidr_mismatch",
            ));
        }
        if !mtls_ok {
            return Err(managed_public_ingress_reject(
                request_id,
                traceparent,
                "Managed public ingress rejected: proxy mTLS identity was not verified",
                "managed_public_ingress_mtls_mismatch",
            ));
        }
        if !relay_token_ok {
            return Err(managed_public_ingress_reject(
                request_id,
                traceparent,
                "Managed public ingress rejected: proxy relay transport token was not verified",
                "managed_public_ingress_transport_token_mismatch",
            ));
        }
        if !hostname_ok {
            return Err(managed_public_ingress_reject(
                request_id,
                traceparent,
                "Managed public ingress rejected: public hostname does not match Host",
                "managed_public_ingress_hostname_mismatch",
            ));
        }
    }

    // Direct caller spoof with no trusted-proxy provenance: strip semantically.
    Ok(ManagedPublicIngressAdmission::Absent)
}

/// Convenience for mutable request maps: admit or physically strip spoofed headers.
pub(crate) fn admit_or_strip_managed_public_ingress(
    headers: &mut HeaderMap,
    peer_ip: std::net::IpAddr,
    trusted_proxy_cidrs: &[ipnet::IpNet],
    tls_config: &crate::gateway::relay::RelayTlsConfig,
    relay_hmac_secret: Option<&str>,
    request_id: &str,
    traceparent: &str,
) -> Result<ManagedPublicIngressAdmission, Response<Body>> {
    let admission = admit_managed_public_ingress(
        headers,
        peer_ip,
        trusted_proxy_cidrs,
        tls_config,
        relay_hmac_secret,
        request_id,
        traceparent,
    )?;
    if matches!(admission, ManagedPublicIngressAdmission::Absent)
        && has_managed_public_ingress_headers(headers)
    {
        strip_managed_public_ingress_headers(headers);
    }
    Ok(admission)
}

pub(crate) fn ingress_marks_managed_public_endpoint(headers: &HeaderMap) -> bool {
    headers
        .get("x-verdictan-public-endpoint")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "managed"
            )
        })
        .unwrap_or(false)
}

pub(crate) fn normalize_managed_public_endpoint_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }

    let host = if let Some((host, port)) = trimmed.rsplit_once(':') {
        if !host.contains(']')
            && host.matches(':').count() == 0
            && port.chars().all(|ch| ch.is_ascii_digit())
        {
            host
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    Some(host.to_ascii_lowercase())
}

pub(crate) fn managed_public_endpoint_host(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-verdictan-public-hostname")
        .or_else(|| headers.get(header::HOST))
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_managed_public_endpoint_host)
}

pub(crate) fn managed_public_endpoint_requested_region_group(
    headers: &HeaderMap,
) -> Option<String> {
    headers
        .get("x-verdictan-requested-region-group")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn publication_state_accepts_public_traffic(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "published" | "draining"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectedCellPoolAdmissionMatch {
    Matched,
    NotMatched,
    Missing,
    Unsupported,
}

pub(crate) fn non_empty_str(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub(crate) fn serving_fleet_class_requires_public_pool_membership(
    serving_fleet_class: &str,
) -> bool {
    serving_fleet_class
        .trim()
        .eq_ignore_ascii_case("connected_cell_pool")
}

pub(crate) fn gateway_identity_matches_candidate(
    candidate: &str,
    runtime_registration_id: Option<&str>,
    gateway_id: Option<&str>,
) -> bool {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return false;
    }

    runtime_registration_id.is_some_and(|value| value.eq_ignore_ascii_case(candidate))
        || gateway_id.is_some_and(|value| value.eq_ignore_ascii_case(candidate))
}

pub(crate) fn admitted_member_status_allows_public_traffic(
    member: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    for key in [
        "admitted",
        "eligible",
        "materialized",
        "healthy",
        "ready",
        "is_admitted",
    ] {
        if let Some(false) = member.get(key).and_then(serde_json::Value::as_bool) {
            return false;
        }
    }

    if let Some(status) = member.get("status").and_then(serde_json::Value::as_str) {
        let status = status.trim().to_ascii_lowercase();
        if !status.is_empty()
            && !matches!(
                status.as_str(),
                "active" | "admitted" | "healthy" | "materialized" | "ready"
            )
        {
            return false;
        }
    }

    true
}

pub(crate) fn evaluate_connected_cell_pool_admitted_members(
    admitted_members: &serde_json::Value,
    runtime_registration_id: Option<&str>,
    gateway_id: Option<&str>,
) -> ConnectedCellPoolAdmissionMatch {
    match admitted_members {
        serde_json::Value::Null => ConnectedCellPoolAdmissionMatch::Missing,
        serde_json::Value::String(candidate) => {
            if gateway_identity_matches_candidate(candidate, runtime_registration_id, gateway_id) {
                ConnectedCellPoolAdmissionMatch::Matched
            } else {
                ConnectedCellPoolAdmissionMatch::NotMatched
            }
        }
        serde_json::Value::Array(entries) => {
            if entries.is_empty() {
                return ConnectedCellPoolAdmissionMatch::NotMatched;
            }

            let mut saw_not_matched = false;
            let mut saw_missing = false;
            for entry in entries {
                match evaluate_connected_cell_pool_admitted_members(
                    entry,
                    runtime_registration_id,
                    gateway_id,
                ) {
                    ConnectedCellPoolAdmissionMatch::Matched => {
                        return ConnectedCellPoolAdmissionMatch::Matched;
                    }
                    ConnectedCellPoolAdmissionMatch::NotMatched => saw_not_matched = true,
                    ConnectedCellPoolAdmissionMatch::Missing => saw_missing = true,
                    ConnectedCellPoolAdmissionMatch::Unsupported => {}
                }
            }

            if saw_not_matched {
                ConnectedCellPoolAdmissionMatch::NotMatched
            } else if saw_missing {
                ConnectedCellPoolAdmissionMatch::Missing
            } else {
                ConnectedCellPoolAdmissionMatch::Unsupported
            }
        }
        serde_json::Value::Object(member) => {
            let mut saw_supported_container = false;
            let mut saw_not_matched = false;
            let mut saw_missing = false;
            for key in [
                "members",
                "admitted_members",
                "gateways",
                "pool_members",
                "runtime_registration_ids",
                "gateway_ids",
                "ids",
            ] {
                if let Some(nested) = member.get(key) {
                    saw_supported_container = true;
                    match evaluate_connected_cell_pool_admitted_members(
                        nested,
                        runtime_registration_id,
                        gateway_id,
                    ) {
                        ConnectedCellPoolAdmissionMatch::Matched => {
                            return ConnectedCellPoolAdmissionMatch::Matched;
                        }
                        ConnectedCellPoolAdmissionMatch::NotMatched => saw_not_matched = true,
                        ConnectedCellPoolAdmissionMatch::Missing => saw_missing = true,
                        ConnectedCellPoolAdmissionMatch::Unsupported => {}
                    }
                }
            }

            let identity_fields = [
                member
                    .get("runtime_registration_id")
                    .and_then(serde_json::Value::as_str),
                member.get("gateway_id").and_then(serde_json::Value::as_str),
                member.get("member_id").and_then(serde_json::Value::as_str),
                member.get("id").and_then(serde_json::Value::as_str),
            ];
            let has_identity_field = identity_fields.iter().any(Option::is_some);

            if has_identity_field {
                if !admitted_member_status_allows_public_traffic(member) {
                    return ConnectedCellPoolAdmissionMatch::NotMatched;
                }

                if identity_fields.into_iter().flatten().any(|candidate| {
                    gateway_identity_matches_candidate(
                        candidate,
                        runtime_registration_id,
                        gateway_id,
                    )
                }) {
                    return ConnectedCellPoolAdmissionMatch::Matched;
                }

                return ConnectedCellPoolAdmissionMatch::NotMatched;
            }

            if saw_supported_container {
                if saw_not_matched {
                    ConnectedCellPoolAdmissionMatch::NotMatched
                } else if saw_missing {
                    ConnectedCellPoolAdmissionMatch::Missing
                } else {
                    ConnectedCellPoolAdmissionMatch::Unsupported
                }
            } else {
                ConnectedCellPoolAdmissionMatch::Unsupported
            }
        }
        _ => ConnectedCellPoolAdmissionMatch::Unsupported,
    }
}

pub(crate) fn active_revision_pool_membership_issue_for_gateway(
    serving_fleet_class: &str,
    runtime_registration_id: Option<&str>,
    gateway_id: Option<&str>,
    admitted_members: Option<&serde_json::Value>,
) -> Option<&'static str> {
    if !serving_fleet_class_requires_public_pool_membership(serving_fleet_class) {
        return None;
    }

    let runtime_registration_id = non_empty_str(runtime_registration_id);
    let gateway_id = non_empty_str(gateway_id);
    if runtime_registration_id.is_none() && gateway_id.is_none() {
        return Some("runtime_pool_identity_missing");
    }

    match evaluate_connected_cell_pool_admitted_members(
        admitted_members.unwrap_or(&serde_json::Value::Null),
        runtime_registration_id,
        gateway_id,
    ) {
        ConnectedCellPoolAdmissionMatch::Matched => None,
        ConnectedCellPoolAdmissionMatch::NotMatched => Some("current_gateway_not_admitted"),
        ConnectedCellPoolAdmissionMatch::Missing => {
            Some("active_revision_admitted_members_missing")
        }
        ConnectedCellPoolAdmissionMatch::Unsupported => {
            Some("active_revision_admitted_members_unrecognized")
        }
    }
}

pub(crate) fn publication_active_revision_accepts_public_traffic(
    publication_state: &str,
    active_revision_readiness_state: &str,
) -> bool {
    let publication_state = publication_state.trim().to_ascii_lowercase();
    let active_revision_readiness_state =
        active_revision_readiness_state.trim().to_ascii_lowercase();
    matches!(
        (
            publication_state.as_str(),
            active_revision_readiness_state.as_str(),
        ),
        ("published", "active") | ("draining", "draining")
    )
}

pub(crate) fn materialize_connected_publication(
    snapshot: &ConnectedGatewayReadModelSnapshot,
    publication: &crate::runtime::ConnectedGatewayPublicationCatalogDescriptor,
) -> crate::runtime::ConnectedGatewayPublicationDescriptor {
    let routing = snapshot.routing_compatibility_for_publication(publication);
    crate::runtime::ConnectedGatewayPublicationDescriptor {
        family_key: publication.family_key.clone(),
        publication_key: publication.publication_key.clone(),
        published_hostname: publication.published_hostname.clone(),
        publication_state: publication.publication_state.clone(),
        active_revision_id: publication.active_revision_id.clone(),
        active_revision_readiness_state: routing.and_then(|value| value.readiness_state.clone()),
        active_revision_auth_digest: routing.and_then(|value| value.auth_digest.clone()),
        active_revision_policy_digest: routing.and_then(|value| value.policy_digest.clone()),
        active_revision_pool_membership_issue: routing
            .and_then(|value| value.active_revision_pool_membership_issue.clone()),
        locality_mode: publication.locality_mode.clone(),
        serving_fleet_class: publication.serving_fleet_class.clone(),
        primary_region_group_key: routing.and_then(|value| value.primary_region_group_key.clone()),
    }
}

pub(crate) fn publication_public_admission_issue(
    publication: &crate::runtime::ConnectedGatewayPublicationDescriptor,
) -> Option<String> {
    if non_empty_str(publication.active_revision_id.as_deref()).is_none() {
        return Some("active_revision_id_missing".to_string());
    }

    let Some(readiness_state) =
        non_empty_str(publication.active_revision_readiness_state.as_deref())
    else {
        return Some("active_revision_readiness_state_missing".to_string());
    };

    if non_empty_str(publication.active_revision_auth_digest.as_deref()).is_none() {
        return Some("active_revision_auth_digest_missing".to_string());
    }

    if non_empty_str(publication.active_revision_policy_digest.as_deref()).is_none() {
        return Some("active_revision_policy_digest_missing".to_string());
    }

    if !publication_active_revision_accepts_public_traffic(
        &publication.publication_state,
        readiness_state,
    ) {
        return Some("active_revision_not_ready_for_public_traffic".to_string());
    }

    if let Some(issue) = non_empty_str(publication.active_revision_pool_membership_issue.as_deref())
    {
        return Some(issue.to_string());
    }

    None
}

/// Validates that a publication's region matches the gateway's configured
/// region. Returns a VDT resource path fragment that includes the
/// publication's region for use in ABAC permission evaluation.
pub(crate) fn publication_region_vrn_resource(
    publication: &crate::runtime::ConnectedGatewayPublicationDescriptor,
    gateway_region_key: Option<&str>,
) -> Option<String> {
    let pub_region = publication.primary_region_group_key.as_deref()?;
    if let Some(gw_region) = gateway_region_key {
        if !gw_region.is_empty() && gw_region != pub_region {
            tracing::warn!(
                publication_key = %publication.publication_key,
                publication_region = pub_region,
                gateway_region = gw_region,
                "region mismatch: publication region does not match gateway region"
            );
            return None;
        }
    }
    Some(format!("publication/{}", publication.publication_key))
}

/// Checks whether a publication's region scope is admissible on this gateway.
/// The gateway must be in the same region as the publication for the request
/// to proceed. Region-pinned managed-public-endpoint traffic therefore fails
/// closed when the gateway lacks region metadata.
pub(crate) fn publication_region_scope_admissible(
    publication: &crate::runtime::ConnectedGatewayPublicationDescriptor,
    gateway_region_key: Option<&str>,
) -> bool {
    let Some(pub_region) = publication
        .primary_region_group_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return true;
    };
    let Some(gw_region) = gateway_region_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        tracing::warn!(
            publication_key = %publication.publication_key,
            publication_region = pub_region,
            "region metadata unavailable for managed public endpoint publication"
        );
        return false;
    };
    gw_region == pub_region
}

pub(crate) fn publication_has_publicly_admissible_active_revision(
    publication: &crate::runtime::ConnectedGatewayPublicationDescriptor,
) -> bool {
    publication_public_admission_issue(publication).is_none()
}

pub(crate) fn publication_public_binding_issue(
    publication: &crate::runtime::ConnectedGatewayPublicationDescriptor,
) -> Option<String> {
    if !publication_state_accepts_public_traffic(&publication.publication_state) {
        return None;
    }

    if publication
        .published_hostname
        .as_deref()
        .and_then(normalize_managed_public_endpoint_host)
        .is_none()
    {
        return Some("published_hostname_missing".to_string());
    }

    publication_public_admission_issue(publication)
}

pub(crate) fn publication_admits_requested_region_group(
    publication: &crate::runtime::ConnectedGatewayPublicationDescriptor,
    requested_region_group: Option<&str>,
) -> bool {
    let Some(requested_region_group) = requested_region_group
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return true;
    };

    if requested_region_group.eq_ignore_ascii_case("global") {
        return true;
    }

    publication
        .primary_region_group_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| value.eq_ignore_ascii_case(requested_region_group))
}

pub(crate) fn publication_matches_requested_managed_public_endpoint(
    publication: &crate::runtime::ConnectedGatewayPublicationCatalogDescriptor,
    requested_host: &str,
) -> bool {
    if !publication_state_accepts_public_traffic(&publication.publication_state) {
        return false;
    }

    let published_host = publication
        .published_hostname
        .as_deref()
        .and_then(normalize_managed_public_endpoint_host);
    published_host.as_deref() == Some(requested_host)
}

pub(crate) fn candidate_managed_public_endpoint_publication(
    snapshot: &ConnectedGatewayReadModelSnapshot,
    requested_host: &str,
) -> Option<crate::runtime::ConnectedGatewayPublicationCatalogDescriptor> {
    if snapshot.cached_negative_lookup_contains(requested_host, Utc::now()) {
        return None;
    }

    let shard_key = managed_public_endpoint_host_shard_key(requested_host);
    let candidate = snapshot
        .publication_catalog_shards
        .get(&shard_key)
        .into_iter()
        .flatten()
        .find(|publication| {
            publication_matches_requested_managed_public_endpoint(publication, requested_host)
        })
        .cloned();
    if candidate.is_none() {
        snapshot.record_negative_lookup(requested_host, Utc::now());
    }
    candidate
}

pub(crate) fn matched_managed_public_endpoint_publication(
    snapshot: &ConnectedGatewayReadModelSnapshot,
    requested_host: &str,
    requested_region_group: Option<&str>,
) -> Option<crate::runtime::ConnectedGatewayPublicationDescriptor> {
    let shard_key = managed_public_endpoint_host_shard_key(requested_host);
    snapshot
        .publication_catalog_shards
        .get(&shard_key)
        .into_iter()
        .flatten()
        .filter(|publication| {
            publication_matches_requested_managed_public_endpoint(publication, requested_host)
        })
        .find_map(|publication| {
            let materialized = materialize_connected_publication(snapshot, publication);
            (publication_admits_requested_region_group(&materialized, requested_region_group)
                && publication_region_scope_admissible(
                    &materialized,
                    snapshot.region_key.as_deref(),
                )
                && publication_public_binding_issue(&materialized).is_none())
            .then_some(materialized)
        })
}

pub(crate) fn locality_scope_fragment(
    requested_region_group: Option<&str>,
    managed_public_endpoint_host: Option<&str>,
) -> Option<String> {
    let requested_region_group = requested_region_group
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let managed_public_endpoint_host = managed_public_endpoint_host
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match (requested_region_group, managed_public_endpoint_host) {
        (Some(region_group), Some(host)) => {
            Some(format!("region_group:{region_group}:host:{host}"))
        }
        (Some(region_group), None) => Some(format!("region_group:{region_group}")),
        (None, Some(host)) => Some(format!("host:{host}")),
        (None, None) => None,
    }
}

pub(crate) fn enforce_managed_public_endpoint_publication_binding(
    connected_read_model: &ConnectedGatewayReadModelSnapshot,
    headers: &HeaderMap,
    request_id: &str,
    traceparent: &str,
) -> Option<Response<Body>> {
    if !ingress_marks_managed_public_endpoint(headers) {
        return None;
    }

    let Some(requested_host) = managed_public_endpoint_host(headers) else {
        return Some(build_response(
            StatusCode::BAD_REQUEST,
            HeaderValue::from_static("application/json"),
            request_id.to_string(),
            traceparent.to_string(),
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "error": error_json(
                        "Managed public endpoint requests must include hostname context",
                        "invalid_request_error",
                        "managed_public_endpoint_missing_host",
                    )
                }))
                .unwrap_or_else(|_| b"{}".to_vec()),
            ),
            false,
            None,
        ));
    };

    let now = Utc::now();
    if connected_read_model.publication_catalog_is_stale(now) {
        let message = match connected_read_model.publication_catalog_age_seconds(now) {
            Some(age_secs) => format!(
                "Managed public endpoint publication catalog is stale on this connected gateway (last successful control-plane refresh was {age_secs}s ago; budget {}s)",
                connected_read_model.stale_after_secs()
            ),
            None => {
                "Managed public endpoint publication catalog has not been refreshed from the control plane yet"
                    .to_string()
            }
        };
        return Some(build_response(
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderValue::from_static("application/json"),
            request_id.to_string(),
            traceparent.to_string(),
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "error": error_json(
                        &message,
                        "service_unavailable",
                        "managed_public_endpoint_publication_catalog_stale",
                    )
                }))
                .unwrap_or_else(|_| b"{}".to_vec()),
            ),
            false,
            None,
        ));
    }

    let requested_region_group = managed_public_endpoint_requested_region_group(headers);
    let candidate =
        candidate_managed_public_endpoint_publication(connected_read_model, &requested_host);
    if candidate.is_none() {
        let message = if let Some(region_group) = requested_region_group.as_deref() {
            format!(
                "Managed public endpoint '{}' is not published on this connected gateway for region group '{}'",
                requested_host, region_group
            )
        } else {
            format!(
                "Managed public endpoint '{}' is not published on this connected gateway",
                requested_host
            )
        };
        return Some(build_response(
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderValue::from_static("application/json"),
            request_id.to_string(),
            traceparent.to_string(),
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "error": error_json(
                        &message,
                        "server_error",
                        "managed_public_endpoint_unpublished",
                    )
                }))
                .unwrap_or_else(|_| b"{}".to_vec()),
            ),
            false,
            None,
        ));
    }

    if connected_read_model.routing_compatibility_is_stale(now) {
        let message = match connected_read_model.routing_compatibility_age_seconds(now) {
            Some(age_secs) => format!(
                "Managed public endpoint routing compatibility data is stale on this connected gateway (last successful control-plane refresh was {age_secs}s ago; budget {}s)",
                connected_read_model.stale_after_secs()
            ),
            None => {
                "Managed public endpoint routing compatibility data has not been refreshed from the control plane yet"
                    .to_string()
            }
        };
        return Some(build_response(
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderValue::from_static("application/json"),
            request_id.to_string(),
            traceparent.to_string(),
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "error": error_json(
                        &message,
                        "service_unavailable",
                        "managed_public_endpoint_routing_compatibility_stale",
                    )
                }))
                .unwrap_or_else(|_| b"{}".to_vec()),
            ),
            false,
            None,
        ));
    }

    let admitted = matched_managed_public_endpoint_publication(
        connected_read_model,
        &requested_host,
        requested_region_group.as_deref(),
    );

    if admitted.is_some() {
        return None;
    }

    let message = if let Some(region_group) = requested_region_group.as_deref() {
        format!(
            "Managed public endpoint '{}' is not published on this connected gateway for region group '{}'",
            requested_host, region_group
        )
    } else {
        format!(
            "Managed public endpoint '{}' is not published on this connected gateway",
            requested_host
        )
    };

    Some(build_response(
        StatusCode::SERVICE_UNAVAILABLE,
        HeaderValue::from_static("application/json"),
        request_id.to_string(),
        traceparent.to_string(),
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "error": error_json(
                    &message,
                    "server_error",
                    "managed_public_endpoint_unpublished",
                )
            }))
            .unwrap_or_else(|_| b"{}".to_vec()),
        ),
        false,
        None,
    ))
}

pub(crate) fn runtime_routing_error_response(
    error: &RuntimeRoutingError,
    request_id: &str,
    traceparent: &str,
) -> Response<Body> {
    build_response(
        error.status(),
        HeaderValue::from_static("application/json"),
        request_id.to_string(),
        traceparent.to_string(),
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "error": error_json(
                    error.browser_safe_message(),
                    "invalid_request_error",
                    error.code(),
                )
            }))
            .unwrap_or_else(|_| b"{}".to_vec()),
        ),
        false,
        None,
    )
}

pub(crate) fn normalize_runtime_plugin_id(value: &str) -> Result<String, RuntimeRoutingError> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    if normalized.is_empty() {
        return Err(RuntimeRoutingError::invalid_request(
            "invalid_plugin_id",
            "Plugin identifiers must not be empty",
        ));
    }
    if normalized
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        Ok(normalized)
    } else {
        Err(RuntimeRoutingError::invalid_request(
            "invalid_plugin_id",
            format!(
                "Plugin identifier '{}' must contain only lowercase ASCII letters, digits, or hyphens",
                value
            ),
        ))
    }
}

pub(crate) fn normalize_runtime_data_collection(
    value: &str,
) -> Result<String, RuntimeRoutingError> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "allow" | "deny" => Ok(normalized),
        _ => Err(RuntimeRoutingError::invalid_request(
            "invalid_data_collection",
            "provider.data_collection must be either 'allow' or 'deny'",
        )),
    }
}

pub(crate) fn parse_runtime_cache_ttl(value: &str) -> Result<Duration, RuntimeRoutingError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RuntimeRoutingError::invalid_request(
            "invalid_cache_ttl",
            "cache_control.ttl must not be empty",
        ));
    }
    let (digits, multiplier) = if let Some(raw) = trimmed.strip_suffix('s') {
        (raw, 1_u64)
    } else if let Some(raw) = trimmed.strip_suffix('m') {
        (raw, 60_u64)
    } else if let Some(raw) = trimmed.strip_suffix('h') {
        (raw, 60_u64 * 60_u64)
    } else {
        (trimmed, 1_u64)
    };
    let seconds = digits.parse::<u64>().map_err(|_| {
        RuntimeRoutingError::invalid_request(
            "invalid_cache_ttl",
            "cache_control.ttl must be an integer optionally suffixed with s, m, or h",
        )
    })?;
    Ok(Duration::from_secs(
        seconds.saturating_mul(multiplier).max(1),
    ))
}

pub(crate) fn resolve_runtime_request_settings(
    state: &mut ActiveGatewayStateView<'_>,
    headers: &HeaderMap,
    request_json: &mut serde_json::Value,
) -> Result<(), RuntimeRoutingError> {
    let silent_engine = silent_engine(state);
    let mut provider_policy = state
        .runtime_routing_settings
        .default_provider_policy
        .clone();
    if let Some(provider) = request_json
        .get("provider")
        .and_then(serde_json::Value::as_object)
    {
        if let Some(value) = provider
            .get("allow_fallbacks")
            .and_then(serde_json::Value::as_bool)
        {
            provider_policy.allow_fallbacks = value;
        }
        if let Some(value) = provider
            .get("require_parameters")
            .and_then(serde_json::Value::as_bool)
        {
            provider_policy.require_parameters = value;
        }
        if let Some(value) = provider
            .get("data_collection")
            .and_then(serde_json::Value::as_str)
        {
            provider_policy.data_collection = normalize_runtime_data_collection(value)?;
        }
        if let Some(value) = provider.get("zdr").and_then(serde_json::Value::as_bool) {
            provider_policy.zdr = value;
        }
    }

    let cache_defaults = &state.runtime_routing_settings.cache_defaults;
    let header_session_id = headers
        .get(cache_defaults.session_header_name.as_str())
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let body_session_id = request_json
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    if (header_session_id.is_some() || body_session_id.is_some())
        && !cache_defaults.allow_session_id
    {
        return Err(RuntimeRoutingError::invalid_request(
            "session_id_not_allowed",
            "session_id routing hints are disabled by the active runtime routing policy",
        ));
    }

    if let (Some(header_session_id), Some(body_session_id)) =
        (header_session_id.as_deref(), body_session_id.as_deref())
    {
        if header_session_id != body_session_id {
            return Err(RuntimeRoutingError::invalid_request(
                "session_id_mismatch",
                "Body session_id must match the configured session header when both are present",
            ));
        }
    }

    let resolved_session_id = body_session_id.or(header_session_id);
    if let Some(session_id) = resolved_session_id.as_ref() {
        request_json["session_id"] = serde_json::Value::String(session_id.clone());
    }
    state.session_id = resolved_session_id;

    let cache_control = request_json.get("cache_control").cloned();
    state.runtime_cache_ttl_override = None;
    if let Some(cache_control) = cache_control {
        if !cache_defaults.allow_cache_control {
            return Err(RuntimeRoutingError::invalid_request(
                "cache_control_not_allowed",
                "cache_control hints are disabled by the active runtime routing policy",
            ));
        }
        let cache_type = cache_control
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("ephemeral")
            .trim()
            .to_ascii_lowercase();
        if cache_type != "ephemeral" {
            return Err(RuntimeRoutingError::invalid_request(
                "invalid_cache_control_type",
                "cache_control.type must currently be 'ephemeral'",
            ));
        }
        let ttl_override = cache_control
            .get("ttl")
            .and_then(serde_json::Value::as_str)
            .map(parse_runtime_cache_ttl)
            .transpose()?;
        state.runtime_cache_ttl_override = ttl_override;
    }

    let privacy_restricted = silent_engine.privacy_enforcement_only()
        || provider_policy.zdr
        || provider_policy.data_collection.eq_ignore_ascii_case("deny");
    let request_plugins = request_json
        .get("plugins")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let prevent_overrides = state
        .runtime_routing_settings
        .plugin_governance
        .prevent_overrides
        .iter()
        .map(|value| normalize_runtime_plugin_id(value))
        .collect::<Result<Vec<_>, _>>()?;
    let forced_on_ids = state
        .runtime_routing_settings
        .plugin_governance
        .forced_on
        .iter()
        .map(|plugin| normalize_runtime_plugin_id(&plugin.id))
        .collect::<Result<Vec<_>, _>>()?;

    let mut plugins_by_id = std::collections::BTreeMap::<String, RuntimePluginSetting>::new();
    for plugin in &state.runtime_routing_settings.plugin_governance.defaults {
        let id = normalize_runtime_plugin_id(&plugin.id)?;
        plugins_by_id.insert(
            id.clone(),
            RuntimePluginSetting {
                id,
                enabled: plugin.enabled,
                options: plugin.options.clone(),
            },
        );
    }

    for plugin in request_plugins {
        let Some(id) = plugin.get("id").and_then(serde_json::Value::as_str) else {
            return Err(RuntimeRoutingError::invalid_request(
                "invalid_plugin_id",
                "Each plugin entry must include a non-empty id",
            ));
        };
        let id = normalize_runtime_plugin_id(id)?;
        let enabled = plugin
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let options = plugin.get("options").cloned();

        if prevent_overrides.contains(&id) {
            if let Some(existing) = plugins_by_id.get(&id) {
                if existing.enabled != enabled || existing.options != options {
                    return Err(RuntimeRoutingError::invalid_request(
                        "plugin_override_forbidden",
                        format!("Plugin '{id}' is governed and cannot be overridden"),
                    ));
                }
            }
        }

        plugins_by_id.insert(
            id.clone(),
            RuntimePluginSetting {
                id,
                enabled,
                options,
            },
        );
    }

    for plugin in &state.runtime_routing_settings.plugin_governance.forced_on {
        let id = normalize_runtime_plugin_id(&plugin.id)?;
        plugins_by_id.insert(
            id.clone(),
            RuntimePluginSetting {
                id,
                enabled: true,
                options: plugin.options.clone(),
            },
        );
    }

    let request_explicit_web_search = request_json
        .get("plugins")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|plugins| {
            plugins.iter().any(|plugin| {
                plugin
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|id| normalize_runtime_plugin_id(id).ok())
                    .is_some_and(|id| id == "web-search")
                    && plugin
                        .get("enabled")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(true)
            })
        });

    if privacy_restricted {
        if forced_on_ids.iter().any(|id| id == "web-search") || request_explicit_web_search {
            return Err(RuntimeRoutingError::invalid_request(
                "privacy_incompatible_plugin",
                "web-search is incompatible with the active privacy policy",
            ));
        }
        if plugins_by_id.remove("web-search").is_some() {
            tracing::debug!("runtime routing removed privacy-incompatible web-search plugin");
        }
    }

    if silent_engine.privacy_enforcement_only() && !plugins_by_id.is_empty() {
        return Err(RuntimeRoutingError::invalid_request(
            "silent_engine_plugin_incompatible",
            "Plugins are disabled while silent engine enforcement is enabled",
        ));
    }

    let plugins = plugins_by_id
        .into_values()
        .map(|plugin| {
            serde_json::json!({
                "id": plugin.id,
                "enabled": plugin.enabled,
                "options": plugin.options,
            })
        })
        .collect::<Vec<_>>();

    request_json["provider"] = serde_json::json!({
        "allow_fallbacks": provider_policy.allow_fallbacks,
        "require_parameters": provider_policy.require_parameters,
        "data_collection": provider_policy.data_collection,
        "zdr": provider_policy.zdr,
    });
    request_json["plugins"] = serde_json::Value::Array(plugins);

    state.runtime_allow_fallbacks = provider_policy.allow_fallbacks;
    state.runtime_privacy_restricted = privacy_restricted;
    state.shadow_routing = EffectiveShadowRouting {
        enabled: !silent_engine.privacy_enforcement_only()
            && state.runtime_routing_settings.shadow_routing.enabled,
        capture_mode: if privacy_restricted {
            "metadata_only".to_string()
        } else {
            state
                .runtime_routing_settings
                .shadow_routing
                .capture_mode
                .clone()
        },
    };
    Ok(())
}

pub(crate) fn runtime_routing_filter_targets(
    state: &ActiveGatewayStateView<'_>,
    targets: &[crate::gateway::providers::ProviderTarget],
    ordered: &[usize],
    request_id: &str,
) -> Result<Vec<usize>, RuntimeRoutingError> {
    let mut filtered = ordered.to_vec();

    if state.runtime_privacy_restricted {
        filtered.retain(|index| {
            let target = &targets[*index];
            let denies_collection = matches!(
                target.data_collection,
                Some(crate::gateway::providers::DataCollectionPolicy::Deny)
            ) || target
                .data_policy
                .as_ref()
                .is_some_and(|policy| policy.zero_data_retention);
            let zdr_eligible = target.zdr
                || target
                    .data_policy
                    .as_ref()
                    .is_some_and(|policy| policy.zero_data_retention);
            denies_collection && zdr_eligible
        });

        if filtered.is_empty() {
            tracing::warn!(
                request_id = %request_id,
                "runtime routing privacy filter removed every provider candidate"
            );
            return Err(RuntimeRoutingError::invalid_request(
                "routing.no_eligible_provider",
                "No eligible provider satisfies the active runtime privacy policy",
            ));
        }
    }

    if state.runtime_routing_settings.cache_defaults.sticky_routing {
        if let Some(session_id) = state.session_id.as_deref() {
            if filtered.len() > 1 {
                use std::hash::{Hash, Hasher};

                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                session_id.hash(&mut hasher);
                state.gateway_id.hash(&mut hasher);
                state
                    .request_finops
                    .as_ref()
                    .and_then(|finops| finops.org_id.as_ref())
                    .hash(&mut hasher);
                state
                    .request_finops
                    .as_ref()
                    .and_then(|finops| finops.key_id.as_ref())
                    .hash(&mut hasher);
                let winner = (hasher.finish() as usize) % filtered.len();
                let selected = filtered.remove(winner);
                filtered.insert(0, selected);
            }
        }
    }

    if !state.runtime_allow_fallbacks && !filtered.is_empty() {
        filtered.truncate(1);
    }

    Ok(filtered)
}

pub(crate) fn effective_cache_ttl_override(state: &ActiveGatewayStateView<'_>) -> Option<Duration> {
    state.runtime_cache_ttl_override.or_else(|| {
        state
            .semantic_cache
            .as_ref()
            .and_then(crate::gateway::cache::SemanticCacheConfig::ttl_override)
    })
}

pub(crate) fn strip_runtime_contract_fields(value: &mut serde_json::Value) {
    if let Some(object) = value.as_object_mut() {
        object.remove("provider");
        object.remove("cache_control");
        object.remove("session_id");
        object.remove("plugins");
    }
}

pub(crate) fn strip_runtime_contract_fields_bytes(body: &Bytes) -> Bytes {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(mut value) => {
            strip_runtime_contract_fields(&mut value);
            serde_json::to_vec(&value)
                .map(Bytes::from)
                .unwrap_or_else(|_| body.clone())
        }
        Err(_) => body.clone(),
    }
}
