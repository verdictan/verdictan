// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use crate::error::CliError;
use crate::gateway::{
    declarative_config::LoadedDeclarativeConfig,
    fail_mode::FailMode,
    server::{self, EventSinkConfig, UpstreamAuthConfig},
};
use crate::instances::GatewayInstanceSpec;
use serde::{Deserialize, Serialize};

fn connected_mode_from_env() -> bool {
    crate::gateway::gateway_env::gateway_control_plane_connected()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectedGatewayPublicationCatalogDescriptor {
    pub family_key: String,
    pub publication_key: String,
    pub published_hostname: Option<String>,
    pub publication_state: String,
    pub active_revision_id: Option<String>,
    pub locality_mode: String,
    pub serving_fleet_class: String,
    #[serde(default)]
    pub agent_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerGatewayDescriptor {
    pub agent_id: String,
    pub gateway_id: String,
    pub relay_endpoint: Option<String>,
    pub readiness: String,
    pub region: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectedGatewayPublicationDescriptor {
    pub family_key: String,
    pub publication_key: String,
    pub published_hostname: Option<String>,
    pub publication_state: String,
    pub active_revision_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_readiness_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_auth_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_policy_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_pool_membership_issue: Option<String>,
    pub locality_mode: String,
    pub serving_fleet_class: String,
    pub primary_region_group_key: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectedGatewayRoutingCompatibilityDescriptor {
    pub publication_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_region_group_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compatibility_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_manifest_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_pool_membership_issue: Option<String>,
}

#[derive(Clone, Debug)]
pub struct RuntimeInstanceConfig {
    pub gateway_id: Option<String>,
    pub runtime_registration_id: Option<String>,
    pub region_key: Option<String>,
    pub publication_catalog: Vec<ConnectedGatewayPublicationCatalogDescriptor>,
    pub routing_compatibility: Vec<ConnectedGatewayRoutingCompatibilityDescriptor>,
    pub source_config_path: Option<String>,
    pub listen: std::net::SocketAddr,
    pub upstream: String,
    pub upstream_auth: Option<UpstreamAuthConfig>,
    pub fail_mode: FailMode,
    pub loaded_config: LoadedDeclarativeConfig,
    pub max_concurrency: usize,
    pub admin_local_only: bool,
    pub event_sink: Option<EventSinkConfig>,
    /// When `true` the gateway requires validated gateway API keys on incoming
    /// requests and enforces org-scoped network controls from those keys.
    pub connected_mode: bool,
    /// Instance-scoped sealed MCP outbox path. When unset, resolved from env at spawn.
    pub mcp_outbox: Option<crate::mcp::audit::McpOutboxHandle>,
}

impl RuntimeInstanceConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gateway_id: Option<String>,
        listen: std::net::SocketAddr,
        upstream: String,
        upstream_auth: Option<UpstreamAuthConfig>,
        fail_mode: FailMode,
        loaded_config: LoadedDeclarativeConfig,
        max_concurrency: usize,
        admin_local_only: bool,
        event_sink: Option<EventSinkConfig>,
    ) -> Self {
        Self {
            gateway_id,
            runtime_registration_id: None,
            region_key: None,
            publication_catalog: Vec::new(),
            routing_compatibility: Vec::new(),
            source_config_path: None,
            listen,
            upstream,
            upstream_auth,
            fail_mode,
            loaded_config,
            max_concurrency: max_concurrency.max(1),
            admin_local_only,
            event_sink,
            connected_mode: false,
            mcp_outbox: None,
        }
    }

    #[allow(dead_code)]
    pub fn from_instance_spec(spec: &GatewayInstanceSpec) -> Result<Self, CliError> {
        let listen = crate::gateway::request_id::parse_listen_addr(&spec.listen_addr)?;
        let fail_mode = FailMode::parse(&spec.fail_mode)
            .ok_or_else(|| CliError::user("invalid persisted fail mode"))?;
        let upstream_auth = spec.upstream_api_key.as_ref().and_then(|secret_ref| {
            secret_ref.resolve().map(|secret| UpstreamAuthConfig {
                header_name: spec
                    .upstream_api_key_header
                    .clone()
                    .unwrap_or_else(|| "Authorization".to_string()),
                header_value: format!(
                    "{}{}",
                    spec.upstream_api_key_prefix
                        .clone()
                        .unwrap_or_else(|| "Bearer ".to_string()),
                    secret
                ),
            })
        });

        let policy_config_paths = spec.policy_config_source.path_values();
        let loaded_config = LoadedDeclarativeConfig::from_paths(
            policy_config_paths.iter().map(std::path::Path::new),
        )?;
        let source_config_path = match policy_config_paths.as_slice() {
            [path] => Some(path.trim().to_string()).filter(|value| !value.is_empty()),
            _ => None,
        };

        let mut config = Self::new(
            Some(spec.gateway_id.clone()),
            listen,
            spec.upstream_base_url.clone(),
            upstream_auth,
            fail_mode,
            loaded_config,
            spec.max_concurrency,
            spec.admin_local_only,
            server::EventSinkConfig::from_env()?,
        )
        .with_connected_mode(connected_mode_from_env());
        config.source_config_path = source_config_path;
        Ok(config)
    }

    pub fn with_connected_mode(mut self, connected_mode: bool) -> Self {
        self.connected_mode = connected_mode;
        self
    }

    #[allow(dead_code)]
    pub async fn spawn(self) -> Result<server::GatewayHandle, CliError> {
        server::spawn_instance(self).await
    }

    pub async fn run_until_ctrl_c(self) -> Result<(), CliError> {
        server::run_instance_until_ctrl_c(self).await
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

    #[test]
    fn publication_catalog_descriptor_serde_round_trip() {
        let desc = ConnectedGatewayPublicationCatalogDescriptor {
            family_key: "prod-family".to_string(),
            publication_key: "pub-001".to_string(),
            published_hostname: Some("api.example.com".to_string()),
            publication_state: "active".to_string(),
            active_revision_id: Some("rev-42".to_string()),
            locality_mode: "regional".to_string(),
            serving_fleet_class: "standard".to_string(),
            agent_id: Some("agent-1".to_string()),
        };
        let json = serde_json::to_string(&desc).unwrap();
        let recovered: ConnectedGatewayPublicationCatalogDescriptor =
            serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.family_key, "prod-family");
        assert_eq!(recovered.publication_key, "pub-001");
        assert_eq!(
            recovered.published_hostname.as_deref(),
            Some("api.example.com")
        );
        assert_eq!(recovered.agent_id.as_deref(), Some("agent-1"));
    }

    #[test]
    fn publication_catalog_descriptor_defaults() {
        let desc = ConnectedGatewayPublicationCatalogDescriptor::default();
        assert!(desc.family_key.is_empty());
        assert!(desc.agent_id.is_none());
    }

    #[test]
    fn peer_gateway_descriptor_serde_round_trip() {
        let desc = PeerGatewayDescriptor {
            agent_id: "agent-peer".to_string(),
            gateway_id: "gw-peer".to_string(),
            relay_endpoint: Some("https://relay.example.com".to_string()),
            readiness: "ready".to_string(),
            region: Some("us-east-1".to_string()),
        };
        let json = serde_json::to_string(&desc).unwrap();
        let recovered: PeerGatewayDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.agent_id, "agent-peer");
        assert_eq!(
            recovered.relay_endpoint.as_deref(),
            Some("https://relay.example.com")
        );
    }

    #[test]
    fn publication_descriptor_serde_round_trip() {
        let desc = ConnectedGatewayPublicationDescriptor {
            family_key: "family".to_string(),
            publication_key: "pub".to_string(),
            published_hostname: None,
            publication_state: "draft".to_string(),
            active_revision_id: None,
            active_revision_readiness_state: Some("pending".to_string()),
            active_revision_auth_digest: Some("sha-auth".to_string()),
            active_revision_policy_digest: None,
            active_revision_pool_membership_issue: None,
            locality_mode: "global".to_string(),
            serving_fleet_class: "premium".to_string(),
            primary_region_group_key: Some("eu-west".to_string()),
        };
        let json = serde_json::to_string(&desc).unwrap();
        let recovered: ConnectedGatewayPublicationDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.publication_state, "draft");
        assert_eq!(
            recovered.active_revision_readiness_state.as_deref(),
            Some("pending")
        );
        assert_eq!(
            recovered.primary_region_group_key.as_deref(),
            Some("eu-west")
        );
    }

    #[test]
    fn routing_compatibility_descriptor_serde_round_trip() {
        let desc = ConnectedGatewayRoutingCompatibilityDescriptor {
            publication_key: "pub-compat".to_string(),
            active_revision_id: Some("rev-1".to_string()),
            primary_region_group_key: Some("us-east".to_string()),
            readiness_state: Some("ready".to_string()),
            compatibility_digest: Some("compat-hash".to_string()),
            auth_digest: None,
            policy_digest: None,
            runtime_manifest_digest: Some("manifest-hash".to_string()),
            active_revision_pool_membership_issue: None,
        };
        let json = serde_json::to_string(&desc).unwrap();
        let recovered: ConnectedGatewayRoutingCompatibilityDescriptor =
            serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.publication_key, "pub-compat");
        assert_eq!(
            recovered.compatibility_digest.as_deref(),
            Some("compat-hash")
        );
    }

    #[test]
    fn routing_compatibility_descriptor_skips_none_fields_in_json() {
        let desc = ConnectedGatewayRoutingCompatibilityDescriptor::default();
        let json = serde_json::to_string(&desc).unwrap();
        assert!(!json.contains("auth_digest"));
        assert!(!json.contains("policy_digest"));
    }

    #[test]
    fn runtime_config_with_connected_mode() {
        let listen: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RuntimeInstanceConfig::new(
            Some("gw-1".to_string()),
            listen,
            "https://api.openai.com".to_string(),
            None,
            FailMode::parse("block").unwrap(),
            LoadedDeclarativeConfig::empty(),
            4,
            true,
            None,
        );
        assert!(!config.connected_mode);
        let config = config.with_connected_mode(true);
        assert!(config.connected_mode);
    }

    #[test]
    fn runtime_config_max_concurrency_clamps_to_one() {
        let listen: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = RuntimeInstanceConfig::new(
            None,
            listen,
            "https://api.openai.com".to_string(),
            None,
            FailMode::parse("allow").unwrap(),
            LoadedDeclarativeConfig::empty(),
            0,
            false,
            None,
        );
        assert_eq!(config.max_concurrency, 1);
    }
}
