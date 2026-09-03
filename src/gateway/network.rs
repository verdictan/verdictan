// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

pub use axum::http::{HeaderMap, Method};
use ipnet::IpNet;
use std::net::IpAddr;
use tower_http::cors::{Any, CorsLayer};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct IpAllowlistConfig {
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Default)]
pub struct CorsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_origins: Vec<String>,
    #[serde(default)]
    pub allow_methods: Vec<String>,
    #[serde(default)]
    pub allow_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default)]
    pub allow_credentials: bool,
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
}

pub fn extract_user_id(headers: &HeaderMap, header_names: &[String]) -> Option<String> {
    for header_name in header_names {
        if let Some(value) = headers.get(header_name) {
            if let Ok(parsed) = value.to_str() {
                let trimmed = parsed.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }

    None
}

pub fn parse_ip_allowlist(config: &IpAllowlistConfig) -> Result<Vec<IpNet>, String> {
    parse_ip_networks(&config.cidrs, "allowlist")
}

pub fn parse_trusted_proxy_cidrs(cidrs: &[String]) -> Result<Vec<IpNet>, String> {
    parse_ip_networks(cidrs, "trusted proxy")
}

fn parse_ip_networks(entries: &[String], kind: &str) -> Result<Vec<IpNet>, String> {
    entries
        .iter()
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .map_err(|error| format!("invalid {kind} CIDR or IP '{entry}': {error}"))
        })
        .collect()
}

pub fn ip_is_allowlisted(ip: IpAddr, allowlist: &[IpNet]) -> bool {
    allowlist.iter().any(|network| network.contains(&ip))
}

/// Returns true when `peer` is inside a non-empty trusted-proxy CIDR set.
///
/// An empty CIDR list means no proxy is trusted for ingress provenance, so
/// caller-supplied managed-public headers must not be accepted from that peer.
pub fn peer_is_trusted_proxy(peer: IpAddr, trusted_proxy_cidrs: &[IpNet]) -> bool {
    !trusted_proxy_cidrs.is_empty() && ip_is_allowlisted(peer, trusted_proxy_cidrs)
}

pub fn build_cors_layer(config: &CorsConfig) -> Option<CorsLayer> {
    if !config.enabled {
        return None;
    }

    let mut layer = CorsLayer::new();

    layer = if config.allow_origins.is_empty() {
        layer.allow_origin(Any)
    } else {
        let origins = config
            .allow_origins
            .iter()
            .filter_map(|origin| origin.parse().ok())
            .collect::<Vec<_>>();
        layer.allow_origin(origins)
    };

    layer = if config.allow_methods.is_empty() {
        layer.allow_methods([Method::GET, Method::POST, Method::OPTIONS])
    } else {
        let methods = config
            .allow_methods
            .iter()
            .filter_map(|method| method.parse::<Method>().ok())
            .collect::<Vec<_>>();
        layer.allow_methods(methods)
    };

    if !config.allow_headers.is_empty() {
        let headers = config
            .allow_headers
            .iter()
            .filter_map(|header| header.parse().ok())
            .collect::<Vec<_>>();
        layer = layer.allow_headers(headers);
    }

    if !config.expose_headers.is_empty() {
        let headers = config
            .expose_headers
            .iter()
            .filter_map(|header| header.parse().ok())
            .collect::<Vec<_>>();
        layer = layer.expose_headers(headers);
    }

    if config.allow_credentials {
        layer = layer.allow_credentials(true);
    }

    if let Some(max_age_seconds) = config.max_age_seconds {
        layer = layer.max_age(std::time::Duration::from_secs(max_age_seconds));
    }

    Some(layer)
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
    use axum::http::HeaderValue;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn extract_user_id_from_first_matching_header() {
        let mut headers = HeaderMap::new();
        headers.insert("X-User-Id", HeaderValue::from_static("user-123"));
        let names = vec!["X-User-Id".to_string()];
        assert_eq!(
            extract_user_id(&headers, &names),
            Some("user-123".to_string())
        );
    }

    #[test]
    fn extract_user_id_tries_multiple_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-User", HeaderValue::from_static("fwd-user"));
        let names = vec!["X-User-Id".to_string(), "X-Forwarded-User".to_string()];
        assert_eq!(
            extract_user_id(&headers, &names),
            Some("fwd-user".to_string())
        );
    }

    #[test]
    fn extract_user_id_skips_empty_values() {
        let mut headers = HeaderMap::new();
        headers.insert("X-User-Id", HeaderValue::from_static("  "));
        headers.insert("X-Alt-User", HeaderValue::from_static("alt-user"));
        let names = vec!["X-User-Id".to_string(), "X-Alt-User".to_string()];
        assert_eq!(
            extract_user_id(&headers, &names),
            Some("alt-user".to_string())
        );
    }

    #[test]
    fn extract_user_id_no_match_returns_none() {
        let headers = HeaderMap::new();
        let names = vec!["X-User-Id".to_string()];
        assert_eq!(extract_user_id(&headers, &names), None);
    }

    #[test]
    fn extract_user_id_trims_value() {
        let mut headers = HeaderMap::new();
        headers.insert("X-User-Id", HeaderValue::from_static("  trimmed  "));
        let names = vec!["X-User-Id".to_string()];
        assert_eq!(
            extract_user_id(&headers, &names),
            Some("trimmed".to_string())
        );
    }

    #[test]
    fn parse_ip_allowlist_cidrs() {
        let config = IpAllowlistConfig {
            cidrs: vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()],
            trusted_proxy_cidrs: Vec::new(),
        };
        let result = parse_ip_allowlist(&config).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn parse_ip_allowlist_single_ip() {
        let config = IpAllowlistConfig {
            cidrs: vec!["192.168.1.1".to_string()],
            trusted_proxy_cidrs: Vec::new(),
        };
        let result = parse_ip_allowlist(&config).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn parse_ip_allowlist_invalid() {
        let config = IpAllowlistConfig {
            cidrs: vec!["not-an-ip".to_string()],
            trusted_proxy_cidrs: Vec::new(),
        };
        assert!(parse_ip_allowlist(&config).is_err());
    }

    #[test]
    fn parse_ip_allowlist_empty() {
        let config = IpAllowlistConfig::default();
        let result = parse_ip_allowlist(&config).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn ip_is_allowlisted_in_range() {
        let config = IpAllowlistConfig {
            cidrs: vec!["10.0.0.0/8".to_string()],
            trusted_proxy_cidrs: Vec::new(),
        };
        let allowlist = parse_ip_allowlist(&config).unwrap();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(ip_is_allowlisted(ip, &allowlist));
    }

    #[test]
    fn ip_is_allowlisted_not_in_range() {
        let config = IpAllowlistConfig {
            cidrs: vec!["10.0.0.0/8".to_string()],
            trusted_proxy_cidrs: Vec::new(),
        };
        let allowlist = parse_ip_allowlist(&config).unwrap();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(!ip_is_allowlisted(ip, &allowlist));
    }

    #[test]
    fn ip_is_allowlisted_empty_list() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(!ip_is_allowlisted(ip, &[]));
    }

    #[test]
    fn ip_is_allowlisted_ipv6() {
        let config = IpAllowlistConfig {
            cidrs: vec!["::1/128".to_string()],
            trusted_proxy_cidrs: Vec::new(),
        };
        let allowlist = parse_ip_allowlist(&config).unwrap();
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(ip_is_allowlisted(ip, &allowlist));
    }

    #[test]
    fn trusted_proxy_peer_requires_non_empty_configured_cidrs() {
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(!peer_is_trusted_proxy(peer, &[]));

        let cidrs = parse_trusted_proxy_cidrs(&["10.0.0.0/8".to_string()]).unwrap();
        assert!(peer_is_trusted_proxy(peer, &cidrs));
        assert!(!peer_is_trusted_proxy(
            "192.168.1.1".parse().unwrap(),
            &cidrs
        ));
    }

    #[test]
    fn build_cors_layer_disabled_returns_none() {
        let config = CorsConfig::default();
        assert!(build_cors_layer(&config).is_none());
    }

    #[test]
    fn build_cors_layer_enabled_returns_some() {
        let config = CorsConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(build_cors_layer(&config).is_some());
    }

    #[test]
    fn ip_allowlist_config_defaults() {
        let config = IpAllowlistConfig::default();
        assert!(config.cidrs.is_empty());
        assert!(config.trusted_proxy_cidrs.is_empty());
    }

    #[test]
    fn cors_config_defaults() {
        let config = CorsConfig::default();
        assert!(!config.enabled);
        assert!(config.allow_origins.is_empty());
        assert!(config.allow_methods.is_empty());
        assert!(config.allow_headers.is_empty());
        assert!(config.expose_headers.is_empty());
        assert!(!config.allow_credentials);
        assert!(config.max_age_seconds.is_none());
    }

    #[test]
    fn build_cors_layer_with_custom_origins() {
        let config = CorsConfig {
            enabled: true,
            allow_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        assert!(build_cors_layer(&config).is_some());
    }

    #[test]
    fn build_cors_layer_with_custom_methods() {
        let config = CorsConfig {
            enabled: true,
            allow_methods: vec!["PUT".to_string(), "DELETE".to_string()],
            ..Default::default()
        };
        assert!(build_cors_layer(&config).is_some());
    }

    #[test]
    fn build_cors_layer_with_allow_headers() {
        let config = CorsConfig {
            enabled: true,
            allow_headers: vec!["Authorization".to_string(), "Content-Type".to_string()],
            ..Default::default()
        };
        assert!(build_cors_layer(&config).is_some());
    }

    #[test]
    fn build_cors_layer_with_expose_headers() {
        let config = CorsConfig {
            enabled: true,
            expose_headers: vec!["X-Request-Id".to_string()],
            ..Default::default()
        };
        assert!(build_cors_layer(&config).is_some());
    }

    #[test]
    fn build_cors_layer_with_credentials() {
        let config = CorsConfig {
            enabled: true,
            allow_origins: vec!["https://app.example.com".to_string()],
            allow_credentials: true,
            ..Default::default()
        };
        assert!(build_cors_layer(&config).is_some());
    }

    #[test]
    fn build_cors_layer_with_max_age() {
        let config = CorsConfig {
            enabled: true,
            max_age_seconds: Some(3600),
            ..Default::default()
        };
        assert!(build_cors_layer(&config).is_some());
    }

    #[test]
    fn build_cors_layer_with_all_options() {
        let config = CorsConfig {
            enabled: true,
            allow_origins: vec!["https://a.com".to_string(), "https://b.com".to_string()],
            allow_methods: vec!["GET".to_string(), "POST".to_string()],
            allow_headers: vec!["Authorization".to_string()],
            expose_headers: vec!["X-Custom".to_string()],
            allow_credentials: true,
            max_age_seconds: Some(7200),
        };
        assert!(build_cors_layer(&config).is_some());
    }

    #[test]
    fn extract_user_id_empty_names_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert("X-User-Id", HeaderValue::from_static("user-1"));
        let names: Vec<String> = vec![];
        assert_eq!(extract_user_id(&headers, &names), None);
    }

    #[test]
    fn parse_ip_allowlist_mixed_v4_v6() {
        let config = IpAllowlistConfig {
            cidrs: vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()],
            trusted_proxy_cidrs: Vec::new(),
        };
        let result = parse_ip_allowlist(&config).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn ip_is_allowlisted_ipv6_not_in_range() {
        let config = IpAllowlistConfig {
            cidrs: vec!["::1/128".to_string()],
            trusted_proxy_cidrs: Vec::new(),
        };
        let allowlist = parse_ip_allowlist(&config).unwrap();
        let ip: IpAddr = "::2".parse().unwrap();
        assert!(!ip_is_allowlisted(ip, &allowlist));
    }

    #[test]
    fn ip_is_allowlisted_exact_match() {
        let config = IpAllowlistConfig {
            cidrs: vec!["192.168.1.100/32".to_string()],
            trusted_proxy_cidrs: Vec::new(),
        };
        let allowlist = parse_ip_allowlist(&config).unwrap();
        assert!(ip_is_allowlisted(
            "192.168.1.100".parse().unwrap(),
            &allowlist
        ));
        assert!(!ip_is_allowlisted(
            "192.168.1.101".parse().unwrap(),
            &allowlist
        ));
    }
}
