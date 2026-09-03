// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Region resolution for CLI commands.

use crate::config::ConfigFile;
use crate::error::CliError;

#[derive(Debug, Clone)]
pub struct RegionConfig {
    pub region: String,
    pub api_url: String,
}

/// Which source won the region resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionSource {
    DeclarativeConfig,
    Flag,
}

impl std::fmt::Display for RegionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeclarativeConfig => f.write_str("declarative config"),
            Self::Flag => f.write_str("--region flag"),
        }
    }
}

/// Resolve region with precedence:
/// declarative_config.region > --region flag > config.default_region
pub fn resolve_region(
    region_flag: Option<&str>,
    config: &ConfigFile,
) -> Result<Option<String>, CliError> {
    resolve_region_with_source(None, region_flag, config).map(|r| r.map(|(region, _)| region))
}

/// Like [`resolve_region`] but also accepts a declarative-config region and
/// returns the winning source for display purposes.
pub fn resolve_region_with_source(
    declarative_region: Option<&str>,
    region_flag: Option<&str>,
    config: &ConfigFile,
) -> Result<Option<(String, RegionSource)>, CliError> {
    if let Some(region) = declarative_region.map(str::trim).filter(|v| !v.is_empty()) {
        return Ok(Some((region.to_string(), RegionSource::DeclarativeConfig)));
    }
    if let Some(region) = region_flag.map(str::trim).filter(|v| !v.is_empty()) {
        return Ok(Some((region.to_string(), RegionSource::Flag)));
    }
    Ok(config
        .default_region
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| (value.to_string(), RegionSource::DeclarativeConfig)))
}

/// Validate that a region slug matches the expected `[a-z]+-[a-z]+` pattern.
pub fn validate_region_slug(region: &str) -> Result<(), CliError> {
    static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        #[allow(clippy::expect_used)]
        regex_lite::Regex::new(r"^[a-z]+-[a-z]+$").expect("region slug regex")
    });
    if region == "global" || re.is_match(region) {
        Ok(())
    } else {
        Err(CliError::user(format!(
            "invalid region slug '{region}': expected format like 'eu-west' or 'us-east'"
        )))
    }
}

/// Resolve per-region API URL from discovery only.
pub async fn resolve_api_url_for_region(
    client: &crate::api::AsyncApiClient,
    region: &str,
) -> Result<String, CliError> {
    #[derive(serde::Deserialize)]
    struct DiscoveryResponse {
        regions: Vec<DiscoveryRegion>,
    }
    #[derive(serde::Deserialize)]
    struct DiscoveryRegion {
        region_key: String,
        api_endpoint: Option<String>,
    }

    let discovery = client
        .get_json::<DiscoveryResponse>("/v1/regions")
        .await
        .map_err(|error| {
            CliError::network(format!(
                "failed to discover api endpoint for region '{region}' via /v1/regions: {error}"
            ))
        })?;

    let entry = discovery
        .regions
        .iter()
        .find(|candidate| candidate.region_key == region)
        .ok_or_else(|| {
            CliError::user(format!(
                "region '{region}' is not available in region discovery"
            ))
        })?;

    entry
        .api_endpoint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            CliError::user(format!(
                "region '{region}' does not publish an api_endpoint in region discovery"
            ))
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
    use crate::api::AsyncApiClient;
    use axum::{http::StatusCode, routing::get, Json, Router};
    use serde_json::json;
    #[test]
    fn display_strings_are_stable() {
        assert_eq!(
            RegionSource::DeclarativeConfig.to_string(),
            "declarative config"
        );
        assert_eq!(RegionSource::Flag.to_string(), "--region flag");
    }

    #[test]
    fn resolve_region_with_source_honors_precedence_and_trims_inputs() {
        let config = ConfigFile {
            api_url: None,
            api_token: None,
            profile: None,
            default_region: Some("global".to_string()),
        };

        let declarative = resolve_region_with_source(Some("  eu-west "), Some("ap-south"), &config)
            .expect("resolve declarative");
        assert_eq!(
            declarative,
            Some(("eu-west".to_string(), RegionSource::DeclarativeConfig))
        );

        let flag = resolve_region_with_source(Some("   "), Some(" ap-south "), &config)
            .expect("resolve flag");
        assert_eq!(flag, Some(("ap-south".to_string(), RegionSource::Flag)));

        let config_region =
            resolve_region_with_source(None, Some("   "), &config).expect("resolve config");
        assert_eq!(
            config_region,
            Some(("global".to_string(), RegionSource::DeclarativeConfig))
        );

        let direct = resolve_region(None, &config).expect("resolve direct");
        assert_eq!(direct, Some("global".to_string()));
    }

    #[test]
    fn resolve_region_with_source_ignores_blank_config_region() {
        let config = ConfigFile {
            api_url: None,
            api_token: None,
            profile: None,
            default_region: Some("   ".to_string()),
        };

        let resolved = resolve_region_with_source(None, None, &config).expect("resolve none");
        assert_eq!(resolved, None);
    }

    #[test]
    fn validate_region_slug_accepts_expected_shapes() {
        assert!(validate_region_slug("eu-west").is_ok());
        assert!(validate_region_slug("global").is_ok());

        let err = validate_region_slug("EU_WEST").expect_err("invalid slug");
        assert!(err
            .to_string()
            .contains("expected format like 'eu-west' or 'us-east'"));
    }
}
