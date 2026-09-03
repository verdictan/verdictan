// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::net::SocketAddr;

use chrono::Utc;

use crate::error::CliError;

use super::SecretReference;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct GatewayInstanceId(String);

impl GatewayInstanceId {
    pub fn new(value: impl Into<String>) -> Result<Self, CliError> {
        let value = value.into();
        validate_instance_name(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for GatewayInstanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyConfigSource {
    Path { path: String },
    Paths { paths: Vec<String> },
    Empty,
}

impl PolicyConfigSource {
    pub fn path(path: impl Into<String>) -> Self {
        Self::Path { path: path.into() }
    }

    pub fn from_paths<I, S>(paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let paths = paths.into_iter().map(Into::into).collect::<Vec<_>>();
        match paths.as_slice() {
            [] => Self::Empty,
            [path] => Self::Path { path: path.clone() },
            _ => Self::Paths { paths },
        }
    }

    pub fn validate(&self) -> Result<(), CliError> {
        match self {
            PolicyConfigSource::Path { path } => {
                if path.trim().is_empty() {
                    Err(CliError::user("policy config path cannot be empty"))
                } else {
                    Ok(())
                }
            }
            PolicyConfigSource::Paths { paths } => {
                if paths.is_empty() {
                    return Err(CliError::user("policy config paths cannot be empty"));
                }
                if paths.iter().any(|path| path.trim().is_empty()) {
                    return Err(CliError::user("policy config path cannot be empty"));
                }
                Ok(())
            }
            PolicyConfigSource::Empty => Ok(()),
        }
    }

    #[allow(dead_code)]
    fn path_value(&self) -> Option<&str> {
        match self {
            PolicyConfigSource::Path { path } => Some(path.as_str()),
            PolicyConfigSource::Paths { paths } => paths.first().map(String::as_str),
            PolicyConfigSource::Empty => None,
        }
    }

    pub fn path_values(&self) -> Vec<&str> {
        match self {
            PolicyConfigSource::Path { path } => vec![path.as_str()],
            PolicyConfigSource::Paths { paths } => paths.iter().map(String::as_str).collect(),
            PolicyConfigSource::Empty => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GatewayInstanceSpec {
    pub instance_id: GatewayInstanceId,
    /// The upstream gateway/proxy ID registered in the Verdictan control plane.
    pub gateway_id: String,
    pub name: String,
    pub listen_addr: String,
    pub upstream_base_url: String,
    pub upstream_api_key: Option<SecretReference>,
    pub upstream_api_key_header: Option<String>,
    pub upstream_api_key_prefix: Option<String>,
    pub fail_mode: String,
    pub policy_config_source: PolicyConfigSource,
    pub max_concurrency: usize,
    pub admin_token: Option<SecretReference>,
    pub admin_local_only: bool,
    pub created_at: String,
}

impl GatewayInstanceSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: GatewayInstanceId,
        gateway_id: impl Into<String>,
        name: impl Into<String>,
        listen_addr: impl Into<String>,
        upstream_base_url: impl Into<String>,
        upstream_api_key: Option<SecretReference>,
        upstream_api_key_header: Option<String>,
        upstream_api_key_prefix: Option<String>,
        fail_mode: impl Into<String>,
        policy_config_source: PolicyConfigSource,
        max_concurrency: usize,
        admin_token: Option<SecretReference>,
        admin_local_only: bool,
    ) -> Result<Self, CliError> {
        let gateway_id = gateway_id.into();
        validate_instance_name(&gateway_id)?;
        let name = name.into();
        validate_instance_name(&name)?;
        let listen_addr = listen_addr.into();
        parse_listen_addr(&listen_addr)?;
        let upstream_base_url = upstream_base_url.into();
        validate_upstream_url(&upstream_base_url)?;
        let fail_mode = fail_mode.into();
        validate_fail_mode(&fail_mode)?;
        policy_config_source.validate()?;
        if let Some(secret_ref) = &upstream_api_key {
            secret_ref.validate()?;
        }
        if let Some(secret_ref) = &admin_token {
            secret_ref.validate()?;
        }

        Ok(Self {
            instance_id,
            gateway_id,
            name,
            listen_addr,
            upstream_base_url,
            upstream_api_key,
            upstream_api_key_header,
            upstream_api_key_prefix,
            fail_mode,
            policy_config_source,
            max_concurrency: max_concurrency.max(1),
            admin_token,
            admin_local_only,
            created_at: Utc::now().to_rfc3339(),
        })
    }

    pub fn validate(&self) -> Result<(), CliError> {
        validate_instance_name(&self.gateway_id)?;
        validate_instance_name(&self.name)?;
        parse_listen_addr(&self.listen_addr)?;
        validate_upstream_url(&self.upstream_base_url)?;
        validate_fail_mode(&self.fail_mode)?;
        self.policy_config_source.validate()?;
        if let Some(secret_ref) = &self.upstream_api_key {
            secret_ref.validate()?;
        }
        if let Some(secret_ref) = &self.admin_token {
            secret_ref.validate()?;
        }
        Ok(())
    }
}

fn validate_instance_name(value: &str) -> Result<(), CliError> {
    let trimmed = value.trim();
    let valid = !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_');
    if valid {
        Ok(())
    } else {
        Err(CliError::user(format!(
            "instance names must be 1-64 characters of [A-Za-z0-9_-]: {}",
            value
        )))
    }
}

fn validate_upstream_url(value: &str) -> Result<(), CliError> {
    let parsed = reqwest::Url::parse(value)
        .map_err(|e| CliError::user(format!("invalid upstream url {}: {e}", value)))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(CliError::user(format!(
            "upstream url must use http or https: {}",
            value
        )));
    }
    Ok(())
}

fn parse_listen_addr(value: &str) -> Result<SocketAddr, CliError> {
    crate::gateway::request_id::parse_listen_addr(value)
}

fn validate_fail_mode(value: &str) -> Result<(), CliError> {
    if matches!(value, "allow" | "block") {
        Ok(())
    } else {
        Err(CliError::user(format!(
            "invalid fail mode {} (expected allow|block)",
            value
        )))
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

    // ── GatewayInstanceId ────────────────────────────────────────────────

    #[test]
    fn instance_id_valid() {
        let id = GatewayInstanceId::new("my-gateway-01").unwrap();
        assert_eq!(id.as_str(), "my-gateway-01");
        assert_eq!(format!("{id}"), "my-gateway-01");
    }

    #[test]
    fn instance_id_underscore() {
        assert!(GatewayInstanceId::new("my_gw").is_ok());
    }

    #[test]
    fn instance_id_empty() {
        assert!(GatewayInstanceId::new("").is_err());
    }

    #[test]
    fn instance_id_too_long() {
        let long = "a".repeat(65);
        assert!(GatewayInstanceId::new(long).is_err());
    }

    #[test]
    fn instance_id_max_length() {
        let exact = "a".repeat(64);
        assert!(GatewayInstanceId::new(exact).is_ok());
    }

    #[test]
    fn instance_id_special_chars() {
        assert!(GatewayInstanceId::new("bad name!").is_err());
        assert!(GatewayInstanceId::new("bad.name").is_err());
    }

    // ── PolicyConfigSource ───────────────────────────────────────────────

    #[test]
    fn policy_source_path() {
        let src = PolicyConfigSource::path("/etc/policy.yaml");
        assert_eq!(
            src,
            PolicyConfigSource::Path {
                path: "/etc/policy.yaml".to_string()
            }
        );
    }

    #[test]
    fn policy_source_from_empty() {
        let src = PolicyConfigSource::from_paths(Vec::<String>::new());
        assert_eq!(src, PolicyConfigSource::Empty);
    }

    #[test]
    fn policy_source_from_single() {
        let src = PolicyConfigSource::from_paths(vec!["single.yaml"]);
        assert!(matches!(src, PolicyConfigSource::Path { .. }));
    }

    #[test]
    fn policy_source_from_multiple() {
        let src = PolicyConfigSource::from_paths(vec!["a.yaml", "b.yaml"]);
        assert!(matches!(src, PolicyConfigSource::Paths { .. }));
    }

    #[test]
    fn policy_source_validate_empty_ok() {
        assert!(PolicyConfigSource::Empty.validate().is_ok());
    }

    #[test]
    fn policy_source_validate_path_ok() {
        assert!(PolicyConfigSource::path("/etc/policy.yaml")
            .validate()
            .is_ok());
    }

    #[test]
    fn policy_source_validate_empty_path_err() {
        let src = PolicyConfigSource::Path {
            path: "  ".to_string(),
        };
        assert!(src.validate().is_err());
    }

    #[test]
    fn policy_source_validate_paths_empty_vec() {
        let src = PolicyConfigSource::Paths { paths: vec![] };
        assert!(src.validate().is_err());
    }

    #[test]
    fn policy_source_validate_paths_with_empty_entry() {
        let src = PolicyConfigSource::Paths {
            paths: vec!["ok.yaml".to_string(), "  ".to_string()],
        };
        assert!(src.validate().is_err());
    }

    #[test]
    fn policy_source_path_value() {
        let src = PolicyConfigSource::path("test.yaml");
        assert_eq!(src.path_value(), Some("test.yaml"));

        assert!(PolicyConfigSource::Empty.path_value().is_none());
    }

    #[test]
    fn policy_source_path_values_multiple() {
        let src = PolicyConfigSource::Paths {
            paths: vec!["a.yaml".to_string(), "b.yaml".to_string()],
        };
        assert_eq!(src.path_values(), vec!["a.yaml", "b.yaml"]);
    }

    #[test]
    fn policy_source_path_values_empty() {
        assert!(PolicyConfigSource::Empty.path_values().is_empty());
    }

    // ── validate_instance_name ───────────────────────────────────────────

    #[test]
    fn validate_name_alphanumeric_dash() {
        assert!(validate_instance_name("abc-123").is_ok());
    }

    #[test]
    fn validate_name_spaces_rejected() {
        assert!(validate_instance_name("has spaces").is_err());
    }

    // ── validate_upstream_url ────────────────────────────────────────────

    #[test]
    fn validate_url_http() {
        assert!(validate_upstream_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn validate_url_https() {
        assert!(validate_upstream_url("https://api.example.com").is_ok());
    }

    #[test]
    fn validate_url_ftp_rejected() {
        assert!(validate_upstream_url("ftp://example.com").is_err());
    }

    #[test]
    fn validate_url_invalid() {
        assert!(validate_upstream_url("not-a-url").is_err());
    }

    // ── validate_fail_mode ───────────────────────────────────────────────

    #[test]
    fn fail_mode_allow() {
        assert!(validate_fail_mode("allow").is_ok());
    }

    #[test]
    fn fail_mode_block() {
        assert!(validate_fail_mode("block").is_ok());
    }

    #[test]
    fn fail_mode_invalid() {
        assert!(validate_fail_mode("ignore").is_err());
    }

    // ── PolicyConfigSource serde ─────────────────────────────────────────

    #[test]
    fn policy_source_serde_roundtrip() {
        let src = PolicyConfigSource::path("my-policy.yaml");
        let json = serde_json::to_string(&src).unwrap();
        let recovered: PolicyConfigSource = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, src);
    }

    #[test]
    fn policy_source_serde_empty() {
        let src = PolicyConfigSource::Empty;
        let json = serde_json::to_string(&src).unwrap();
        let recovered: PolicyConfigSource = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, src);
    }
}
