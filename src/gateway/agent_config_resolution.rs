// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use crate::error::CliError;

use super::{
    AgentMcpConfig, ContextFabricConfig, ContextFabricPeerConfig, GatewayAgentDeclaration,
    LoadedDeclarativeConfig, MatchListOrWildcard, McpServerConfig,
};

const DEFAULT_CAPTURE_MODE: &str = "nudge";
const DEFAULT_POOL_MAX_ENTRIES: u32 = 10_000;
const DEFAULT_DEDUP_SIMILARITY_THRESHOLD: f64 = 0.95;
const DEFAULT_COMPACTION_SIMILARITY_THRESHOLD: f64 = 0.92;
const DEFAULT_CONFLICT_RESOLUTION_STRATEGY: &str = "SourceTypeWins";
const DEFAULT_L1_ENABLED: bool = true;
const DEFAULT_L1_MAX_ENTRIES: u32 = 100;
const DEFAULT_L2_BLOOM_FALSE_POSITIVE_RATE: f64 = 0.05;
const DEFAULT_VECTOR_CONFIDENCE_THRESHOLD: f64 = 0.7;
const DEFAULT_PRECOMPUTE_ENABLED: bool = true;
const DEFAULT_PRECOMPUTE_DEBOUNCE_MS: u64 = 500;
const DEFAULT_HNSW_EF_CONSTRUCT: u32 = 128;
const DEFAULT_HNSW_M: u32 = 16;
const DEFAULT_MULTI_GATEWAY_ENABLED: bool = false;
const DEFAULT_MULTI_GATEWAY_SYNC_INTERVAL_MS: u64 = 100;
const DEFAULT_MULTI_GATEWAY_MAX_PARTITION_BUFFER_AGE: &str = "24h";
const DEFAULT_MCP_MAX_PROMPT_BYTES: u64 = 100_000;
const DEFAULT_MCP_MAX_CONCURRENT_SESSIONS: u32 = 10;

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedContextFabricTtlConfig {
    pub auto_captured_days: Option<u32>,
    pub manual_days: Option<u32>,
    pub verified_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedContextFabricConfidenceConfig {
    pub votes_for_verified: Option<u32>,
    pub auto_flag_stale_after_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedContextFabricCacheConfig {
    pub l1_enabled: bool,
    pub l1_max_entries: u32,
    pub redis_url: Option<String>,
    pub l2_bloom_false_positive_rate: f64,
    pub vector_confidence_threshold: f64,
    pub precompute_enabled: bool,
    pub precompute_debounce_ms: u64,
    pub hnsw_ef_construct: u32,
    pub hnsw_m: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedContextFabricMultiGatewayConfig {
    pub enabled: bool,
    pub peers: Vec<ContextFabricPeerConfig>,
    pub sync_interval_ms: u64,
    pub max_partition_buffer_age: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedContextFabricConfig {
    pub enabled: bool,
    pub capture_mode: String,
    pub capture_exclude_patterns: Vec<String>,
    pub pool_max_entries: u32,
    pub ttl: ResolvedContextFabricTtlConfig,
    pub dedup_similarity_threshold: f64,
    pub compaction_similarity_threshold: f64,
    pub pii_detection: bool,
    pub dlp_filter: bool,
    pub confidence: ResolvedContextFabricConfidenceConfig,
    pub branch_inheritance: Option<bool>,
    pub direct_answer_threshold: Option<f64>,
    pub cache: ResolvedContextFabricCacheConfig,
    pub conflict_resolution_strategy: String,
    pub multi_gateway: ResolvedContextFabricMultiGatewayConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedMcpSessionLimitsConfig {
    pub max_prompt_bytes: u64,
    pub max_test_inference_cost_usd: Option<f64>,
    pub max_concurrent_sessions: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedMcpToolServerPolicyConfig {
    pub allow_unapproved: bool,
    pub allowed_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedMcpConfig {
    pub enabled: bool,
    pub path: Option<String>,
    pub allowed_tools: MatchListOrWildcard,
    pub allowed_resources: MatchListOrWildcard,
    pub max_request_body_bytes: Option<u64>,
    pub auth_mode: Option<String>,
    pub default_capture_mode: Option<String>,
    pub session_limits: ResolvedMcpSessionLimitsConfig,
    pub tool_servers: ResolvedMcpToolServerPolicyConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedAgentConfig {
    pub agent_id: String,
    pub team: String,
    pub context_fabric: ResolvedContextFabricConfig,
    pub mcp: ResolvedMcpConfig,
}

pub fn resolve_agent_config(
    config: &LoadedDeclarativeConfig,
    agent_id: &str,
) -> Option<ResolvedAgentConfig> {
    let agent = config
        .agents
        .iter()
        .find(|candidate| candidate.id == agent_id)?;
    Some(resolve_declared_agent_config(
        agent,
        config.context_fabric.as_ref(),
        config.mcp_server.as_ref(),
    ))
}

pub fn resolve_agent_config_for_binding(
    config: &LoadedDeclarativeConfig,
    bound_agent_id: Option<&str>,
) -> Result<ResolvedAgentConfig, CliError> {
    if let Some(agent_id) = bound_agent_id
        .map(str::trim)
        .filter(|agent_id| !agent_id.is_empty())
    {
        return resolve_agent_config(config, agent_id).ok_or_else(|| {
            CliError::user(format!(
                "no declarative agent config found for agent id '{}'",
                agent_id
            ))
        });
    }

    if let Some(default_agent_id) = config
        .agents_runtime
        .as_ref()
        .and_then(|runtime| runtime.default_agent_id.as_deref())
        .map(str::trim)
        .filter(|agent_id| !agent_id.is_empty())
    {
        return resolve_agent_config(config, default_agent_id).ok_or_else(|| {
            CliError::user(format!(
                "default_agent_id '{}' does not match any declared agents[] entry",
                default_agent_id
            ))
        });
    }

    if config.agents.len() == 1 {
        return Ok(resolve_declared_agent_config(
            &config.agents[0],
            config.context_fabric.as_ref(),
            config.mcp_server.as_ref(),
        ));
    }

    Err(CliError::user(
        "unable to resolve agent-scoped config without an authenticated or default agent binding"
            .to_string(),
    ))
}

pub fn resolve_declared_agent_config(
    agent: &GatewayAgentDeclaration,
    gateway_context_fabric: Option<&ContextFabricConfig>,
    gateway_mcp_server: Option<&McpServerConfig>,
) -> ResolvedAgentConfig {
    ResolvedAgentConfig {
        agent_id: agent.id.clone(),
        team: agent.team.clone(),
        context_fabric: resolve_context_fabric_config(
            agent.context_fabric.as_ref(),
            gateway_context_fabric,
            gateway_mcp_server,
        ),
        mcp: resolve_mcp_config(agent.mcp.as_ref(), gateway_mcp_server),
    }
}

fn resolve_context_fabric_config(
    agent: Option<&ContextFabricConfig>,
    gateway: Option<&ContextFabricConfig>,
    gateway_mcp_server: Option<&McpServerConfig>,
) -> ResolvedContextFabricConfig {
    let gateway_ttl = gateway.and_then(|cfg| cfg.ttl.as_ref());
    let agent_ttl = agent.and_then(|cfg| cfg.ttl.as_ref());
    let gateway_confidence = gateway.and_then(|cfg| cfg.confidence.as_ref());
    let agent_confidence = agent.and_then(|cfg| cfg.confidence.as_ref());
    let gateway_cache = gateway.and_then(|cfg| cfg.cache.as_ref());
    let agent_cache = agent.and_then(|cfg| cfg.cache.as_ref());
    let gateway_multi_gateway = gateway.and_then(|cfg| cfg.multi_gateway.as_ref());
    let agent_multi_gateway = agent.and_then(|cfg| cfg.multi_gateway.as_ref());

    ResolvedContextFabricConfig {
        enabled: pick_bool(
            agent.and_then(|cfg| cfg.enabled),
            gateway.and_then(|cfg| cfg.enabled),
            true,
        ),
        capture_mode: pick_string(
            agent.and_then(|cfg| cfg.capture_mode.as_ref()),
            gateway
                .and_then(|cfg| cfg.capture_mode.as_ref())
                .or_else(|| gateway_mcp_server.and_then(|cfg| cfg.default_capture_mode.as_ref())),
            DEFAULT_CAPTURE_MODE,
        ),
        capture_exclude_patterns: pick_vec_string(
            agent.and_then(|cfg| cfg.capture_exclude_patterns.as_ref()),
            gateway.and_then(|cfg| cfg.capture_exclude_patterns.as_ref()),
        ),
        pool_max_entries: pick_u32(
            agent.and_then(|cfg| cfg.pool_max_entries),
            gateway.and_then(|cfg| cfg.pool_max_entries),
            DEFAULT_POOL_MAX_ENTRIES,
        ),
        ttl: ResolvedContextFabricTtlConfig {
            auto_captured_days: pick_option_u32(
                agent_ttl.and_then(|cfg| cfg.auto_captured_days),
                gateway_ttl.and_then(|cfg| cfg.auto_captured_days),
            ),
            manual_days: pick_option_u32(
                agent_ttl.and_then(|cfg| cfg.manual_days),
                gateway_ttl.and_then(|cfg| cfg.manual_days),
            ),
            verified_days: pick_option_u32(
                agent_ttl.and_then(|cfg| cfg.verified_days),
                gateway_ttl.and_then(|cfg| cfg.verified_days),
            ),
        },
        dedup_similarity_threshold: pick_f64(
            agent.and_then(|cfg| cfg.dedup_similarity_threshold),
            gateway.and_then(|cfg| cfg.dedup_similarity_threshold),
            DEFAULT_DEDUP_SIMILARITY_THRESHOLD,
        ),
        compaction_similarity_threshold: pick_f64(
            agent.and_then(|cfg| cfg.compaction_similarity_threshold),
            gateway.and_then(|cfg| cfg.compaction_similarity_threshold),
            DEFAULT_COMPACTION_SIMILARITY_THRESHOLD,
        ),
        pii_detection: pick_bool(
            agent.and_then(|cfg| cfg.pii_detection),
            gateway.and_then(|cfg| cfg.pii_detection),
            true,
        ),
        dlp_filter: pick_bool(
            agent.and_then(|cfg| cfg.dlp_filter),
            gateway.and_then(|cfg| cfg.dlp_filter),
            true,
        ),
        confidence: ResolvedContextFabricConfidenceConfig {
            votes_for_verified: pick_option_u32(
                agent_confidence.and_then(|cfg| cfg.votes_for_verified),
                gateway_confidence.and_then(|cfg| cfg.votes_for_verified),
            ),
            auto_flag_stale_after_days: pick_option_u32(
                agent_confidence.and_then(|cfg| cfg.auto_flag_stale_after_days),
                gateway_confidence.and_then(|cfg| cfg.auto_flag_stale_after_days),
            ),
        },
        branch_inheritance: pick_option_bool(
            agent.and_then(|cfg| cfg.branch_inheritance),
            gateway.and_then(|cfg| cfg.branch_inheritance),
        ),
        direct_answer_threshold: pick_option_f64(
            agent.and_then(|cfg| cfg.direct_answer_threshold),
            gateway.and_then(|cfg| cfg.direct_answer_threshold),
        ),
        cache: ResolvedContextFabricCacheConfig {
            l1_enabled: pick_bool(
                agent_cache.and_then(|cfg| cfg.l1_enabled),
                gateway_cache.and_then(|cfg| cfg.l1_enabled),
                DEFAULT_L1_ENABLED,
            ),
            l1_max_entries: pick_u32(
                agent_cache.and_then(|cfg| cfg.l1_max_entries),
                gateway_cache.and_then(|cfg| cfg.l1_max_entries),
                DEFAULT_L1_MAX_ENTRIES,
            ),
            redis_url: pick_option_string(
                agent_cache.and_then(|cfg| cfg.redis_url.as_ref()),
                gateway_cache.and_then(|cfg| cfg.redis_url.as_ref()),
            ),
            l2_bloom_false_positive_rate: pick_f64(
                agent_cache.and_then(|cfg| cfg.l2_bloom_false_positive_rate),
                gateway_cache.and_then(|cfg| cfg.l2_bloom_false_positive_rate),
                DEFAULT_L2_BLOOM_FALSE_POSITIVE_RATE,
            ),
            vector_confidence_threshold: pick_f64(
                agent_cache.and_then(|cfg| cfg.vector_confidence_threshold),
                gateway_cache.and_then(|cfg| cfg.vector_confidence_threshold),
                DEFAULT_VECTOR_CONFIDENCE_THRESHOLD,
            ),
            precompute_enabled: pick_bool(
                agent_cache.and_then(|cfg| cfg.precompute_enabled),
                gateway_cache.and_then(|cfg| cfg.precompute_enabled),
                DEFAULT_PRECOMPUTE_ENABLED,
            ),
            precompute_debounce_ms: pick_u64(
                agent_cache.and_then(|cfg| cfg.precompute_debounce_ms),
                gateway_cache.and_then(|cfg| cfg.precompute_debounce_ms),
                DEFAULT_PRECOMPUTE_DEBOUNCE_MS,
            ),
            hnsw_ef_construct: pick_u32(
                agent_cache.and_then(|cfg| cfg.hnsw_ef_construct),
                gateway_cache.and_then(|cfg| cfg.hnsw_ef_construct),
                DEFAULT_HNSW_EF_CONSTRUCT,
            ),
            hnsw_m: pick_u32(
                agent_cache.and_then(|cfg| cfg.hnsw_m),
                gateway_cache.and_then(|cfg| cfg.hnsw_m),
                DEFAULT_HNSW_M,
            ),
        },
        conflict_resolution_strategy: pick_string(
            agent.and_then(|cfg| cfg.conflict_resolution_strategy.as_ref()),
            gateway.and_then(|cfg| cfg.conflict_resolution_strategy.as_ref()),
            DEFAULT_CONFLICT_RESOLUTION_STRATEGY,
        ),
        multi_gateway: ResolvedContextFabricMultiGatewayConfig {
            enabled: pick_bool(
                agent_multi_gateway.and_then(|cfg| cfg.enabled),
                gateway_multi_gateway.and_then(|cfg| cfg.enabled),
                DEFAULT_MULTI_GATEWAY_ENABLED,
            ),
            peers: pick_vec_peer_config(
                agent_multi_gateway.and_then(|cfg| cfg.peers.as_ref()),
                gateway_multi_gateway.and_then(|cfg| cfg.peers.as_ref()),
            ),
            sync_interval_ms: pick_u64(
                agent_multi_gateway.and_then(|cfg| cfg.sync_interval_ms),
                gateway_multi_gateway.and_then(|cfg| cfg.sync_interval_ms),
                DEFAULT_MULTI_GATEWAY_SYNC_INTERVAL_MS,
            ),
            max_partition_buffer_age: pick_string(
                agent_multi_gateway.and_then(|cfg| cfg.max_partition_buffer_age.as_ref()),
                gateway_multi_gateway.and_then(|cfg| cfg.max_partition_buffer_age.as_ref()),
                DEFAULT_MULTI_GATEWAY_MAX_PARTITION_BUFFER_AGE,
            ),
        },
    }
}

fn resolve_mcp_config(
    agent: Option<&AgentMcpConfig>,
    gateway: Option<&McpServerConfig>,
) -> ResolvedMcpConfig {
    let gateway_session_limits = gateway.and_then(|cfg| cfg.session_limits.as_ref());
    let agent_session_limits = agent.and_then(|cfg| cfg.session_limits.as_ref());
    let gateway_tool_servers = gateway.and_then(|cfg| cfg.tool_servers.as_ref());
    let agent_tool_servers = agent.and_then(|cfg| cfg.tool_servers.as_ref());

    ResolvedMcpConfig {
        enabled: compose_mcp_enabled(
            agent.and_then(|cfg| cfg.enabled),
            gateway.and_then(|cfg| cfg.enabled),
        ),
        path: gateway.and_then(|cfg| cfg.path.clone()),
        allowed_tools: compose_match_list(
            agent.and_then(|cfg| cfg.allowed_tools.as_ref()),
            gateway.and_then(|cfg| cfg.allowed_tools.as_ref()),
        ),
        allowed_resources: compose_match_list(
            agent.and_then(|cfg| cfg.allowed_resources.as_ref()),
            gateway.and_then(|cfg| cfg.allowed_resources.as_ref()),
        ),
        max_request_body_bytes: gateway.and_then(|cfg| cfg.max_request_body_bytes),
        auth_mode: gateway.and_then(|cfg| cfg.auth_mode.clone()),
        default_capture_mode: gateway.and_then(|cfg| cfg.default_capture_mode.clone()),
        session_limits: ResolvedMcpSessionLimitsConfig {
            max_prompt_bytes: compose_u64_limit(
                agent_session_limits.and_then(|cfg| cfg.max_prompt_bytes),
                gateway_session_limits.and_then(|cfg| cfg.max_prompt_bytes),
                DEFAULT_MCP_MAX_PROMPT_BYTES,
            ),
            max_test_inference_cost_usd: compose_optional_f64_limit(
                agent_session_limits.and_then(|cfg| cfg.max_test_inference_cost_usd),
                gateway_session_limits.and_then(|cfg| cfg.max_test_inference_cost_usd),
            ),
            max_concurrent_sessions: compose_u32_limit(
                agent_session_limits.and_then(|cfg| cfg.max_concurrent_sessions),
                gateway_session_limits.and_then(|cfg| cfg.max_concurrent_sessions),
                DEFAULT_MCP_MAX_CONCURRENT_SESSIONS,
            ),
        },
        tool_servers: ResolvedMcpToolServerPolicyConfig {
            allow_unapproved: compose_allow_unapproved_tool_servers(
                agent_tool_servers.and_then(|cfg| cfg.allow_unapproved),
                gateway_tool_servers.and_then(|cfg| cfg.allow_unapproved),
            ),
            allowed_ids: compose_allowed_ids(
                agent_tool_servers.and_then(|cfg| cfg.allowed_ids.as_ref()),
                gateway_tool_servers.and_then(|cfg| cfg.allowed_ids.as_ref()),
            ),
        },
    }
}

fn pick_bool(agent: Option<bool>, gateway: Option<bool>, default: bool) -> bool {
    agent.or(gateway).unwrap_or(default)
}

fn compose_mcp_enabled(agent: Option<bool>, gateway: Option<bool>) -> bool {
    gateway.unwrap_or(true) && agent.unwrap_or(true)
}

fn pick_u32(agent: Option<u32>, gateway: Option<u32>, default: u32) -> u32 {
    agent.or(gateway).unwrap_or(default)
}

fn pick_u64(agent: Option<u64>, gateway: Option<u64>, default: u64) -> u64 {
    agent.or(gateway).unwrap_or(default)
}

fn pick_f64(agent: Option<f64>, gateway: Option<f64>, default: f64) -> f64 {
    agent.or(gateway).unwrap_or(default)
}

fn pick_string(agent: Option<&String>, gateway: Option<&String>, default: &str) -> String {
    agent
        .cloned()
        .or_else(|| gateway.cloned())
        .unwrap_or_else(|| default.to_string())
}

fn pick_vec_string(agent: Option<&Vec<String>>, gateway: Option<&Vec<String>>) -> Vec<String> {
    agent
        .cloned()
        .or_else(|| gateway.cloned())
        .unwrap_or_default()
}

fn pick_vec_peer_config(
    agent: Option<&Vec<ContextFabricPeerConfig>>,
    gateway: Option<&Vec<ContextFabricPeerConfig>>,
) -> Vec<ContextFabricPeerConfig> {
    agent
        .cloned()
        .or_else(|| gateway.cloned())
        .unwrap_or_default()
}

fn compose_match_list(
    agent: Option<&MatchListOrWildcard>,
    gateway: Option<&MatchListOrWildcard>,
) -> MatchListOrWildcard {
    match (agent, gateway) {
        (
            Some(MatchListOrWildcard::Explicit(agent_values)),
            Some(MatchListOrWildcard::Explicit(gateway_values)),
        ) => MatchListOrWildcard::Explicit(intersect_preserving_left_order(
            gateway_values,
            agent_values,
        )),
        (Some(MatchListOrWildcard::Explicit(values)), _) => {
            MatchListOrWildcard::Explicit(values.clone())
        }
        (Some(MatchListOrWildcard::Wildcard), Some(MatchListOrWildcard::Explicit(values))) => {
            MatchListOrWildcard::Explicit(values.clone())
        }
        (None, Some(values)) => values.clone(),
        _ => MatchListOrWildcard::Wildcard,
    }
}

fn compose_u32_limit(agent: Option<u32>, gateway: Option<u32>, default: u32) -> u32 {
    agent.unwrap_or(default).min(gateway.unwrap_or(default))
}

fn compose_u64_limit(agent: Option<u64>, gateway: Option<u64>, default: u64) -> u64 {
    agent.unwrap_or(default).min(gateway.unwrap_or(default))
}

fn compose_optional_f64_limit(agent: Option<f64>, gateway: Option<f64>) -> Option<f64> {
    match (agent, gateway) {
        (Some(agent), Some(gateway)) => Some(agent.min(gateway)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn compose_allow_unapproved_tool_servers(agent: Option<bool>, gateway: Option<bool>) -> bool {
    gateway.unwrap_or(false) && agent.unwrap_or(true)
}

fn compose_allowed_ids(agent: Option<&Vec<String>>, gateway: Option<&Vec<String>>) -> Vec<String> {
    match (agent, gateway) {
        (Some(agent_values), Some(gateway_values))
            if !agent_values.is_empty() && !gateway_values.is_empty() =>
        {
            intersect_preserving_left_order(gateway_values, agent_values)
        }
        (Some(values), _) if !values.is_empty() => values.clone(),
        (_, Some(values)) if !values.is_empty() => values.clone(),
        _ => Vec::new(),
    }
}

fn intersect_preserving_left_order(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .filter(|value| right.iter().any(|candidate| candidate == *value))
        .cloned()
        .collect()
}

fn pick_option_bool(agent: Option<bool>, gateway: Option<bool>) -> Option<bool> {
    agent.or(gateway)
}

fn pick_option_u32(agent: Option<u32>, gateway: Option<u32>) -> Option<u32> {
    agent.or(gateway)
}

fn pick_option_f64(agent: Option<f64>, gateway: Option<f64>) -> Option<f64> {
    agent.or(gateway)
}

fn pick_option_string(agent: Option<&String>, gateway: Option<&String>) -> Option<String> {
    agent.cloned().or_else(|| gateway.cloned())
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
    use crate::gateway::declarative_config::{
        ContextFabricCacheConfig, ContextFabricConfidenceConfig, ContextFabricMultiGatewayConfig,
        ContextFabricPeerConfig, ContextFabricTtlConfig, McpSessionLimitsConfig,
        McpToolServerPolicyConfig,
    };

    #[test]
    fn resolve_declared_agent_config_applies_agent_gateway_and_system_defaults() {
        let agent = GatewayAgentDeclaration {
            id: "code-assistant".to_string(),
            team: "backend-eng".to_string(),
            context_fabric: Some(ContextFabricConfig {
                enabled: Some(false),
                capture_mode: None,
                capture_exclude_patterns: Some(vec!["target/".to_string()]),
                pool_max_entries: None,
                ttl: None,
                dedup_similarity_threshold: Some(0.88),
                compaction_similarity_threshold: None,
                pii_detection: None,
                dlp_filter: None,
                confidence: None,
                branch_inheritance: Some(true),
                direct_answer_threshold: Some(0.6),
                cache: Some(ContextFabricCacheConfig {
                    l1_enabled: Some(false),
                    l1_max_entries: Some(500),
                    redis_url: None,
                    l2_bloom_false_positive_rate: None,
                    vector_confidence_threshold: Some(0.61),
                    precompute_enabled: Some(false),
                    precompute_debounce_ms: Some(1_200),
                    hnsw_ef_construct: Some(256),
                    hnsw_m: None,
                }),
                conflict_resolution_strategy: Some("VoteWins".to_string()),
                multi_gateway: Some(ContextFabricMultiGatewayConfig {
                    enabled: Some(true),
                    peers: Some(vec![ContextFabricPeerConfig {
                        gateway_id: "00000000-0000-4000-a000-0000000000b0".to_string(),
                        endpoint: "https://agent-b.verdictan.example/internal/crdt/sync"
                            .to_string(),
                    }]),
                    sync_interval_ms: None,
                    max_partition_buffer_age: Some("48h".to_string()),
                }),
            }),
            mcp: Some(AgentMcpConfig {
                enabled: None,
                allowed_tools: Some(MatchListOrWildcard::Explicit(vec![
                    "models_list".to_string()
                ])),
                allowed_resources: None,
                session_limits: Some(McpSessionLimitsConfig {
                    max_prompt_bytes: Some(50_000),
                    max_test_inference_cost_usd: None,
                    max_concurrent_sessions: None,
                }),
                tool_servers: Some(McpToolServerPolicyConfig {
                    allow_unapproved: Some(false),
                    allowed_ids: Some(vec!["postgres".to_string()]),
                }),
            }),
        };
        let gateway_context = ContextFabricConfig {
            enabled: Some(true),
            capture_mode: Some("auto".to_string()),
            capture_exclude_patterns: None,
            pool_max_entries: Some(25_000),
            ttl: Some(ContextFabricTtlConfig {
                auto_captured_days: Some(14),
                manual_days: Some(90),
                verified_days: Some(365),
            }),
            dedup_similarity_threshold: None,
            compaction_similarity_threshold: Some(0.9),
            pii_detection: Some(false),
            dlp_filter: Some(true),
            confidence: Some(ContextFabricConfidenceConfig {
                votes_for_verified: Some(3),
                auto_flag_stale_after_days: Some(30),
            }),
            branch_inheritance: None,
            direct_answer_threshold: None,
            cache: Some(ContextFabricCacheConfig {
                l1_enabled: Some(true),
                l1_max_entries: Some(250),
                redis_url: Some("redis://cache.internal:6379/0".to_string()),
                l2_bloom_false_positive_rate: Some(0.04),
                vector_confidence_threshold: Some(0.72),
                precompute_enabled: Some(true),
                precompute_debounce_ms: Some(600),
                hnsw_ef_construct: Some(192),
                hnsw_m: Some(24),
            }),
            conflict_resolution_strategy: Some("SourceTypeWins".to_string()),
            multi_gateway: Some(ContextFabricMultiGatewayConfig {
                enabled: Some(false),
                peers: Some(vec![ContextFabricPeerConfig {
                    gateway_id: "00000000-0000-4000-a000-0000000000a0".to_string(),
                    endpoint: "https://agent-a.verdictan.example/internal/crdt/sync".to_string(),
                }]),
                sync_interval_ms: Some(250),
                max_partition_buffer_age: Some("24h".to_string()),
            }),
        };
        let gateway_mcp = McpServerConfig {
            enabled: Some(true),
            path: Some("/mcp".to_string()),
            allowed_tools: Some(MatchListOrWildcard::Explicit(vec![
                "chat_test".to_string(),
                "models_list".to_string(),
            ])),
            allowed_resources: Some(MatchListOrWildcard::Wildcard),
            max_request_body_bytes: Some(131_072),
            auth_mode: Some("bearer".to_string()),
            default_capture_mode: Some("nudge".to_string()),
            session_limits: Some(McpSessionLimitsConfig {
                max_prompt_bytes: Some(120_000),
                max_test_inference_cost_usd: Some(2.5),
                max_concurrent_sessions: Some(4),
            }),
            tool_servers: Some(McpToolServerPolicyConfig {
                allow_unapproved: Some(true),
                allowed_ids: Some(vec!["postgres".to_string(), "redis".to_string()]),
            }),
        };

        let resolved =
            resolve_declared_agent_config(&agent, Some(&gateway_context), Some(&gateway_mcp));

        assert_eq!(resolved.agent_id, "code-assistant");
        assert!(!resolved.context_fabric.enabled);
        assert_eq!(resolved.context_fabric.capture_mode, "auto");
        assert_eq!(
            resolved.context_fabric.capture_exclude_patterns,
            vec!["target/"]
        );
        assert_eq!(resolved.context_fabric.pool_max_entries, 25_000);
        assert_eq!(resolved.context_fabric.ttl.auto_captured_days, Some(14));
        assert_eq!(resolved.context_fabric.dedup_similarity_threshold, 0.88);
        assert_eq!(resolved.context_fabric.compaction_similarity_threshold, 0.9);
        assert!(!resolved.context_fabric.pii_detection);
        assert_eq!(
            resolved.context_fabric.confidence.votes_for_verified,
            Some(3)
        );
        assert_eq!(resolved.context_fabric.branch_inheritance, Some(true));
        assert_eq!(resolved.context_fabric.direct_answer_threshold, Some(0.6));
        assert!(!resolved.context_fabric.cache.l1_enabled);
        assert_eq!(resolved.context_fabric.cache.l1_max_entries, 500);
        assert_eq!(
            resolved.context_fabric.cache.redis_url.as_deref(),
            Some("redis://cache.internal:6379/0")
        );
        assert_eq!(
            resolved.context_fabric.cache.vector_confidence_threshold,
            0.61
        );
        assert_eq!(resolved.context_fabric.cache.hnsw_ef_construct, 256);
        assert_eq!(resolved.context_fabric.cache.hnsw_m, 24);
        assert_eq!(
            resolved.context_fabric.conflict_resolution_strategy,
            "VoteWins"
        );
        assert!(resolved.context_fabric.multi_gateway.enabled);
        assert_eq!(
            resolved.context_fabric.multi_gateway.peers,
            vec![ContextFabricPeerConfig {
                gateway_id: "00000000-0000-4000-a000-0000000000b0".to_string(),
                endpoint: "https://agent-b.verdictan.example/internal/crdt/sync".to_string(),
            }]
        );
        assert_eq!(resolved.context_fabric.multi_gateway.sync_interval_ms, 250);
        assert_eq!(
            resolved
                .context_fabric
                .multi_gateway
                .max_partition_buffer_age,
            "48h"
        );

        assert!(resolved.mcp.enabled);
        assert_eq!(resolved.mcp.path.as_deref(), Some("/mcp"));
        assert_eq!(
            resolved.mcp.allowed_tools,
            MatchListOrWildcard::Explicit(vec!["models_list".to_string()])
        );
        assert_eq!(
            resolved.mcp.allowed_resources,
            MatchListOrWildcard::Wildcard
        );
        assert_eq!(resolved.mcp.session_limits.max_prompt_bytes, 50_000);
        assert_eq!(
            resolved.mcp.session_limits.max_test_inference_cost_usd,
            Some(2.5)
        );
        assert_eq!(resolved.mcp.session_limits.max_concurrent_sessions, 4);
        assert!(!resolved.mcp.tool_servers.allow_unapproved);
        assert_eq!(resolved.mcp.tool_servers.allowed_ids, vec!["postgres"]);
    }

    #[test]
    fn resolve_declared_agent_config_uses_system_defaults_when_gateway_and_agent_omit_values() {
        let agent = GatewayAgentDeclaration {
            id: "research-agent".to_string(),
            team: "data-science".to_string(),
            context_fabric: None,
            mcp: None,
        };

        let resolved = resolve_declared_agent_config(&agent, None, None);

        assert!(resolved.context_fabric.enabled);
        assert_eq!(resolved.context_fabric.capture_mode, "nudge");
        assert_eq!(resolved.context_fabric.pool_max_entries, 10_000);
        assert_eq!(resolved.context_fabric.dedup_similarity_threshold, 0.95);
        assert_eq!(
            resolved.context_fabric.compaction_similarity_threshold,
            0.92
        );
        assert!(resolved.context_fabric.pii_detection);
        assert!(resolved.context_fabric.dlp_filter);

        assert!(resolved.mcp.enabled);
        assert_eq!(resolved.mcp.allowed_tools, MatchListOrWildcard::Wildcard);
        assert_eq!(
            resolved.mcp.allowed_resources,
            MatchListOrWildcard::Wildcard
        );
        assert_eq!(resolved.mcp.session_limits.max_prompt_bytes, 100_000);
        assert_eq!(resolved.mcp.session_limits.max_concurrent_sessions, 10);
        assert!(!resolved.mcp.tool_servers.allow_unapproved);
        assert!(resolved.mcp.tool_servers.allowed_ids.is_empty());
    }

    #[test]
    fn resolve_agent_config_for_binding_uses_sole_declared_agent() {
        let config = LoadedDeclarativeConfig::from_bytes(
            br#"
agents:
  - id: code-assistant
    team: backend-eng
"#,
        )
        .expect("config should parse");

        let resolved =
            resolve_agent_config_for_binding(&config, None).expect("sole agent should resolve");

        assert_eq!(resolved.agent_id, "code-assistant");
        assert_eq!(resolved.team, "backend-eng");
    }

    #[test]
    fn resolve_agent_config_for_binding_reports_missing_agent() {
        let config = LoadedDeclarativeConfig::from_bytes(
            br#"
agents:
  - id: code-assistant
    team: backend-eng
"#,
        )
        .expect("config should parse");

        let error = resolve_agent_config_for_binding(&config, Some("missing-agent"))
            .expect_err("missing agent should error");

        assert!(
            error
                .to_string()
                .contains("no declarative agent config found for agent id 'missing-agent'"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn resolve_context_fabric_capture_mode_falls_back_to_mcp_server_default_capture_mode() {
        let agent = GatewayAgentDeclaration {
            id: "research-agent".to_string(),
            team: "data-science".to_string(),
            context_fabric: None,
            mcp: None,
        };
        let gateway_mcp = McpServerConfig {
            enabled: Some(true),
            path: Some("/mcp".to_string()),
            allowed_tools: None,
            allowed_resources: None,
            max_request_body_bytes: None,
            auth_mode: Some("bearer".to_string()),
            default_capture_mode: Some("auto".to_string()),
            session_limits: None,
            tool_servers: None,
        };

        let resolved = resolve_declared_agent_config(&agent, None, Some(&gateway_mcp));

        assert_eq!(resolved.context_fabric.capture_mode, "auto");
    }
}
