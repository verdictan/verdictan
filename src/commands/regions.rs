// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan regions` command group — list, status, switch, current, use (Phase 40).

use clap::{Args, Subcommand};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::api::AsyncApiClient;
use crate::commands::configure;
use crate::config::{sources, ConfigFile, DEFAULT_API_URL};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Clone, Args)]
pub struct RegionsArgs {
    #[command(subcommand)]
    pub command: RegionsCommand,

    #[arg(long, global = true)]
    pub config: Option<std::path::PathBuf>,

    #[arg(long, global = true)]
    pub api_url: Option<String>,

    #[arg(long, global = true)]
    pub api_token: Option<String>,

    #[arg(long, global = true, default_value = "default")]
    pub profile: String,

    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Debug, Clone, Subcommand)]
pub enum RegionsCommand {
    /// List available regions from the region discovery API.
    List {
        /// Only show enabled regions.
        #[arg(long)]
        enabled: bool,
        /// Only show disabled regions.
        #[arg(long)]
        disabled: bool,
        /// Filter results by one primary region group key.
        #[arg(long)]
        group: Option<String>,
        /// Filter results by one sovereignty class.
        #[arg(long = "sovereignty-class")]
        sovereignty_class: Option<String>,
    },
    /// Set the CLI config region in ~/.verdictan/config.yaml.
    Use {
        /// Region key to set as default (for example, eu-west or us-east).
        region: String,
    },
    /// Show detailed status for each region (health, gateway count, last heartbeat).
    Status,
    /// Set the CLI config region (alias for `use`).
    Switch {
        /// Region key to switch to (for example, eu-west or us-east).
        region: String,
    },
    /// Display the currently configured region with its precedence source.
    Current,
}

#[derive(Debug, Clone)]
pub(crate) struct RegionListFilters {
    pub(crate) enabled: bool,
    pub(crate) disabled: bool,
    pub(crate) group: Option<String>,
    pub(crate) sovereignty_class: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiscoveryResponse {
    regions: Vec<PublicRegionInfo>,
}

#[derive(Debug, Deserialize)]
struct PublicCatalogResponse {
    regions: Vec<PublicCatalogRegionInfo>,
}

#[derive(Debug, Deserialize)]
struct OrganizationRegionsResponse {
    #[serde(default)]
    cells: Vec<OrganizationRegionInfo>,
}

#[derive(Debug, Deserialize)]
struct OrganizationRegionInfo {
    region_key: String,
    name: String,
    status: String,
    sovereignty_class: String,
    primary_region_group_key: String,
    #[serde(default)]
    default_currency: String,
    #[serde(default)]
    customer_api_origin: Option<String>,
    #[serde(default)]
    customer_console_origin: Option<String>,
    #[serde(default)]
    family_bindings: Vec<OrganizationRegionFamilyBinding>,
}

#[derive(Debug, Deserialize)]
struct OrganizationRegionFamilyBinding {
    family_key: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct PublicRegionInfo {
    region_key: String,
    display_name: String,
    sovereignty_class: String,
    lifecycle_state: String,
    #[serde(default)]
    api_endpoint: Option<String>,
    #[serde(default)]
    console_endpoint: Option<String>,
    #[serde(default)]
    family_memberships: Vec<String>,
    #[serde(default)]
    default_currency: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RegionListItem {
    region_key: String,
    display_name: String,
    sovereignty_class: String,
    lifecycle_state: String,
    api_endpoint: Option<String>,
    console_endpoint: Option<String>,
    family_memberships: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    primary_region_group_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    visible_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_home_region: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegionsListJson {
    regions: Vec<RegionListItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_region_source: Option<String>,
    resolved_api_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_region_scope: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct RegionResolutionContext {
    effective_profile: String,
    default_region: Option<String>,
    requested_region: Option<String>,
    requested_region_source: Option<String>,
    requested_region_scope: Option<RequestedRegionScope>,
    resolved_api_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct PublicCatalogRegionInfo {
    region_key: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    sovereignty_class: Option<String>,
    #[serde(default)]
    lifecycle_state: Option<String>,
    #[serde(default)]
    api_endpoint: Option<String>,
    #[serde(default)]
    console_endpoint: Option<String>,
    #[serde(default)]
    family_memberships: Vec<String>,
    #[serde(default)]
    default_currency: Option<String>,
}

impl From<PublicCatalogRegionInfo> for PublicRegionInfo {
    fn from(value: PublicCatalogRegionInfo) -> Self {
        Self {
            display_name: value
                .display_name
                .unwrap_or_else(|| value.region_key.clone()),
            sovereignty_class: value
                .sovereignty_class
                .unwrap_or_else(|| "public".to_string()),
            lifecycle_state: value
                .lifecycle_state
                .unwrap_or_else(|| "unknown".to_string()),
            api_endpoint: value.api_endpoint,
            console_endpoint: value.console_endpoint,
            family_memberships: value.family_memberships,
            default_currency: value.default_currency,
            region_key: value.region_key,
        }
    }
}

impl From<PublicRegionInfo> for RegionListItem {
    fn from(value: PublicRegionInfo) -> Self {
        let enabled_region =
            matches!(value.lifecycle_state.as_str(), "active").then(|| value.region_key.clone());
        let visible_region = Some(value.region_key.clone());
        let resource_home_region = Some(value.region_key.clone());

        Self {
            region_key: value.region_key,
            display_name: value.display_name,
            sovereignty_class: value.sovereignty_class,
            lifecycle_state: value.lifecycle_state,
            api_endpoint: value.api_endpoint,
            console_endpoint: value.console_endpoint,
            family_memberships: value.family_memberships,
            primary_region_group_key: None,
            default_currency: value.default_currency,
            enabled_region,
            visible_region,
            default_region: None,
            requested_region: None,
            resource_home_region,
        }
    }
}

impl From<OrganizationRegionInfo> for RegionListItem {
    fn from(value: OrganizationRegionInfo) -> Self {
        let family_memberships = value
            .family_bindings
            .into_iter()
            .map(|binding| binding.family_key)
            .collect::<Vec<_>>();
        let enabled_region =
            matches!(value.status.as_str(), "active").then(|| value.region_key.clone());
        let visible_region = Some(value.region_key.clone());
        let resource_home_region = Some(value.region_key.clone());

        Self {
            region_key: value.region_key,
            display_name: value.name,
            sovereignty_class: value.sovereignty_class,
            lifecycle_state: value.status,
            api_endpoint: value.customer_api_origin,
            console_endpoint: value.customer_console_origin,
            family_memberships,
            primary_region_group_key: Some(value.primary_region_group_key),
            default_currency: Some(value.default_currency),
            enabled_region,
            visible_region,
            default_region: None,
            requested_region: None,
            resource_home_region,
        }
    }
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct RegionStatusInfo {
    region_key: String,
    display_name: String,
    lifecycle_state: String,
    #[serde(default)]
    api_endpoint: Option<String>,
    #[serde(default)]
    gateway_count: Option<u64>,
    #[serde(default)]
    active_sessions: Option<u64>,
    #[serde(default)]
    last_heartbeat: Option<String>,
    #[serde(default)]
    default_currency: Option<String>,
}

pub fn run(args: RegionsArgs) -> Result<(), CliError> {
    match args.command.clone() {
        RegionsCommand::List {
            enabled,
            disabled,
            group,
            sovereignty_class,
        } => run_list(
            args,
            RegionListFilters {
                enabled,
                disabled,
                group,
                sovereignty_class,
            },
        ),
        RegionsCommand::Use { region } => {
            let config_path = args.config.clone();
            run_use(config_path, args.profile, region)
        }
        RegionsCommand::Status => run_status(args),
        RegionsCommand::Switch { region } => {
            let config_path = args.config.clone();
            run_use(config_path, args.profile, region)
        }
        RegionsCommand::Current => run_current(args),
    }
}

fn run_list(args: RegionsArgs, filters: RegionListFilters) -> Result<(), CliError> {
    tokio::runtime::Runtime::new()
        .map_err(|e| CliError::internal(format!("failed to create async runtime: {e}")))?
        .block_on(run_list_async(args, filters))
}

pub(crate) async fn run_list_async(
    args: RegionsArgs,
    filters: RegionListFilters,
) -> Result<(), CliError> {
    validate_list_filters(&filters)?;

    let api_url = args
        .api_url
        .clone()
        .or_else(sources::load_api_url_from_env)
        .unwrap_or_else(|| DEFAULT_API_URL.to_string());
    let resolution = resolve_region_context(&args)?;

    let mut regions = if let Some(token) = resolve_token(&args)? {
        fetch_authenticated_regions(&api_url, &token).await?
    } else {
        if filters.group.is_some() {
            return Err(CliError::user(
                "`verdictan regions list --group` requires authenticated organization region metadata",
            ));
        }
        fetch_public_regions(&api_url)
            .await?
            .regions
            .into_iter()
            .map(RegionListItem::from)
            .collect::<Vec<_>>()
    };
    apply_resolution_metadata(&mut regions, &resolution);
    apply_filters(&mut regions, &filters);

    if args.json {
        print_json(&RegionsListJson {
            regions,
            profile: Some(resolution.effective_profile),
            default_region: resolution.default_region,
            requested_region: resolution.requested_region.clone(),
            resolved_region: resolution.requested_region,
            resolved_region_source: resolution.requested_region_source,
            resolved_api_endpoint: resolution.resolved_api_endpoint,
            requested_region_scope: resolution
                .requested_region_scope
                .map(RequestedRegionScope::as_str),
        })?;
        return Ok(());
    }

    if regions.is_empty() {
        println!("no regions matched filters");
        return Ok(());
    }

    println!(
        "{:<12} {:<20} {:<18} {:<12} {:<10} API ENDPOINT",
        "REGION", "DISPLAY", "SOVEREIGNTY", "LIFECYCLE", "CURRENCY"
    );
    println!("{}", "-".repeat(100));
    for region in &regions {
        println!(
            "{:<12} {:<20} {:<18} {:<12} {:<10} {}",
            region.region_key,
            truncate(&region.display_name, 20),
            truncate(&region.sovereignty_class, 18),
            region.lifecycle_state,
            region.default_currency.as_deref().unwrap_or("-"),
            region.api_endpoint.as_deref().unwrap_or("-"),
        );
    }

    Ok(())
}

fn run_status(args: RegionsArgs) -> Result<(), CliError> {
    tokio::runtime::Runtime::new()
        .map_err(|e| CliError::internal(format!("failed to create async runtime: {e}")))?
        .block_on(run_status_async(args))
}

pub(crate) async fn run_status_async(args: RegionsArgs) -> Result<(), CliError> {
    let api_url = args
        .api_url
        .clone()
        .or_else(sources::load_api_url_from_env)
        .unwrap_or_else(|| DEFAULT_API_URL.to_string());

    let client = if let Some(token) = resolve_token(&args)? {
        AsyncApiClient::new(&api_url, token)?
    } else {
        AsyncApiClient::new(&api_url, "")?
    };

    let value = client.get_json_value("/v1/regions").await?;
    let regions: Vec<RegionStatusInfo> = value
        .get("regions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default();

    if args.json {
        print_json(&regions)?;
        return Ok(());
    }

    if regions.is_empty() {
        println!("no regions available");
        return Ok(());
    }

    for region in &regions {
        println!("{}:", region.region_key);
        println!("  display:        {}", region.display_name);
        println!("  lifecycle:      {}", region.lifecycle_state);
        println!(
            "  api endpoint:   {}",
            region.api_endpoint.as_deref().unwrap_or("-")
        );
        println!(
            "  currency:       {}",
            region.default_currency.as_deref().unwrap_or("-")
        );
        println!(
            "  gateways:       {}",
            region
                .gateway_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        println!(
            "  active sessions: {}",
            region
                .active_sessions
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
        println!(
            "  last heartbeat: {}",
            region.last_heartbeat.as_deref().unwrap_or("-")
        );
        println!();
    }

    Ok(())
}

fn run_current(args: RegionsArgs) -> Result<(), CliError> {
    let resolution = resolve_region_context(&args)?;

    if args.json {
        let value = match (
            resolution.requested_region.as_ref(),
            resolution.requested_region_source.as_ref(),
            resolution.requested_region_scope,
        ) {
            (Some(region), Some(source), Some(scope)) => serde_json::json!({
                "region": region,
                "source": source,
                "resolved_region": region,
                "resolved_region_source": source,
                "resolved_api_endpoint": resolution.resolved_api_endpoint,
                "requested_region_scope": scope.as_str(),
                "profile": resolution.effective_profile,
                "default_region": resolution.default_region,
                "requested_region": region,
            }),
            _ => serde_json::json!({
                "region": null,
                "source": null,
                "resolved_region": null,
                "resolved_region_source": null,
                "resolved_api_endpoint": resolution.resolved_api_endpoint,
                "requested_region_scope": null,
                "profile": resolution.effective_profile,
                "default_region": resolution.default_region,
                "requested_region": null,
            }),
        };
        return print_json(&value);
    }

    match (
        resolution.requested_region.as_ref(),
        resolution.requested_region_source.as_ref(),
        resolution.requested_region_scope,
    ) {
        (Some(region), Some(source), Some(scope)) => {
            println!("current region: {region}");
            println!("source: {source}");
            println!("profile: {}", resolution.effective_profile);
            println!(
                "resolved api endpoint: {}",
                resolution.resolved_api_endpoint
            );
            println!("requested region scope: {}", scope.as_str());
            println!();
            println!("precedence chain:");
            println!(
                "  1. VERDICTAN_REGION env:      {}",
                check_source("VERDICTAN_REGION env", source, region)
            );
            println!(
                "  2. profile default region:     {}",
                check_source(
                    format!("profile '{}' default_region", resolution.effective_profile).as_str(),
                    source,
                    region
                )
            );
            println!(
                "  3. declarative config region:  {}",
                check_source("declarative config", source, region)
            );
        }
        _ => {
            println!("no region configured");
            println!("profile: {}", resolution.effective_profile);
            println!(
                "resolved api endpoint: {}",
                resolution.resolved_api_endpoint
            );
            println!();
            println!("set a region with:");
            println!("  verdictan configure set region <region> --profile <profile>");
            println!("  verdictan regions use <region> --profile <profile>");
            println!("  --region <region>");
        }
    }

    Ok(())
}

fn resolve_region_context(args: &RegionsArgs) -> Result<RegionResolutionContext, CliError> {
    let config_path = args.config.as_deref();
    let file = sources::load_config_file(config_path)?;
    let effective_profile = effective_profile(&args.profile, &file);
    let profiled_region = sources::load_profile_region_config(config_path, &effective_profile)?;
    let env_region = std::env::var("VERDICTAN_REGION")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let default_region = profiled_region
        .profile_default_region
        .clone()
        .or(profiled_region.legacy_default_region.clone());
    let requested_region = env_region.clone().or_else(|| default_region.clone());
    let requested_region_source = env_region
        .as_ref()
        .map(|_| "VERDICTAN_REGION env".to_string())
        .or_else(|| {
            profiled_region
                .profile_default_region
                .as_ref()
                .map(|_| format!("profile '{effective_profile}' default_region"))
        })
        .or_else(|| {
            profiled_region
                .legacy_default_region
                .as_ref()
                .map(|_| "declarative config".to_string())
        });
    let requested_region_scope = requested_region
        .as_deref()
        .map(|region| RequestedRegionScope::from_region(Some(region)));

    Ok(RegionResolutionContext {
        effective_profile,
        default_region,
        requested_region,
        requested_region_source,
        requested_region_scope,
        resolved_api_endpoint: resolve_current_api_endpoint(args, &file),
    })
}

async fn fetch_authenticated_regions(
    api_url: &str,
    token: &str,
) -> Result<Vec<RegionListItem>, CliError> {
    let client = AsyncApiClient::new(api_url, token)?;
    let response: OrganizationRegionsResponse = client.get_json("/v1/organization/regions").await?;
    Ok(response
        .cells
        .into_iter()
        .map(RegionListItem::from)
        .collect())
}

fn validate_list_filters(filters: &RegionListFilters) -> Result<(), CliError> {
    if filters.enabled && filters.disabled {
        return Err(CliError::user(
            "`verdictan regions list` cannot combine --enabled and --disabled",
        ));
    }
    Ok(())
}

fn apply_resolution_metadata(regions: &mut [RegionListItem], resolution: &RegionResolutionContext) {
    for region in regions {
        region.default_region = resolution.default_region.clone();
        region.requested_region = resolution.requested_region.clone();
    }
}

fn apply_filters(regions: &mut Vec<RegionListItem>, filters: &RegionListFilters) {
    let sovereignty_class = filters
        .sovereignty_class
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase);
    let group = filters
        .group
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);

    regions.retain(|region| {
        if filters.enabled && region.enabled_region.is_none() {
            return false;
        }
        if filters.disabled && region.enabled_region.is_some() {
            return false;
        }
        if let Some(expected) = sovereignty_class.as_deref() {
            if !region.sovereignty_class.eq_ignore_ascii_case(expected) {
                return false;
            }
        }
        if let Some(expected_group) = group.as_deref() {
            if region.primary_region_group_key.as_deref() != Some(expected_group) {
                return false;
            }
        }
        true
    });
}

fn check_source(check: &str, active: &str, region: &str) -> String {
    if check == active {
        format!("{region} (active)")
    } else {
        "-".to_string()
    }
}

pub(crate) fn run_use(
    config_path_flag: Option<std::path::PathBuf>,
    profile: String,
    region_key: String,
) -> Result<(), CliError> {
    let config_path = configure::write_profile_region(config_path_flag, &profile, &region_key)?;

    println!(
        "Configured region set to '{}' in {}",
        region_key.trim(),
        config_path.display()
    );
    Ok(())
}

fn effective_profile(profile_arg: &str, file: &ConfigFile) -> String {
    if profile_arg == "default" {
        file.profile
            .clone()
            .unwrap_or_else(|| "default".to_string())
    } else {
        profile_arg.to_string()
    }
}

fn resolve_current_api_endpoint(args: &RegionsArgs, file: &ConfigFile) -> String {
    args.api_url
        .clone()
        .or_else(sources::load_api_url_from_env)
        .or_else(|| file.api_url.clone())
        .unwrap_or_else(|| DEFAULT_API_URL.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestedRegionScope {
    Global,
    Regional,
}

impl RequestedRegionScope {
    fn from_region(region: Option<&str>) -> Self {
        match region.map(str::trim) {
            Some("global") => Self::Global,
            Some(_) => Self::Regional,
            None => Self::Global,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Regional => "regional",
        }
    }
}

fn resolve_token(args: &RegionsArgs) -> Result<Option<String>, CliError> {
    if let Some(token) = &args.api_token {
        return Ok(Some(token.clone()));
    }
    sources::load_api_token_from_env()
}

async fn fetch_public_regions(api_url: &str) -> Result<DiscoveryResponse, CliError> {
    fetch_public_regions_from_path(api_url, "/v1/regions")
        .await
        .map_err(PublicRegionFetchError::into_cli_error)
}

async fn fetch_public_regions_from_path(
    api_url: &str,
    path: &str,
) -> Result<DiscoveryResponse, PublicRegionFetchError> {
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("verdictan-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| {
            PublicRegionFetchError::Cli(CliError::internal(format!(
                "failed to build public regions client: {error}"
            )))
        })?
        .get(join_url(api_url, path))
        .header("x-client-surface", "cli")
        .send()
        .await
        .map_err(|error| {
            PublicRegionFetchError::Cli(CliError::network(format!(
                "failed to fetch public region catalog: {error}"
            )))
        })?;

    let status = response.status();
    if !status.is_success() {
        return Err(PublicRegionFetchError::Status(status));
    }

    let value = response
        .json::<serde_json::Value>()
        .await
        .map_err(|error| {
            PublicRegionFetchError::Cli(CliError::network(format!(
                "failed to decode public region catalog: {error}"
            )))
        })?;

    if let Ok(discovery) = serde_json::from_value::<DiscoveryResponse>(value.clone()) {
        return Ok(discovery);
    }

    let public = serde_json::from_value::<PublicCatalogResponse>(value).map_err(|error| {
        PublicRegionFetchError::Cli(CliError::network(format!(
            "failed to parse public region catalog: {error}"
        )))
    })?;

    Ok(DiscoveryResponse {
        regions: public
            .regions
            .into_iter()
            .map(PublicRegionInfo::from)
            .collect(),
    })
}

fn join_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

enum PublicRegionFetchError {
    Cli(CliError),
    Status(StatusCode),
}

impl PublicRegionFetchError {
    fn into_cli_error(self) -> CliError {
        match self {
            Self::Cli(error) => error,
            Self::Status(status) => {
                CliError::network(format!("public region catalog request failed ({status})"))
            }
        }
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        format!("{}…", &value[..max.saturating_sub(1)])
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
    fn truncate_preserves_short_values_and_ellipsizes_long_values() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("abcdefghij", 5), "abcd…");
    }

    #[test]
    fn truncate_exact_length_no_ellipsis() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_single_char_limit() {
        let result = truncate("abcdef", 1);
        assert!(result.contains('…'));
    }

    #[test]
    fn effective_profile_prefers_file_profile_when_arg_is_default() {
        let file = ConfigFile {
            profile: Some("workspace".to_string()),
            ..Default::default()
        };
        assert_eq!(effective_profile("default", &file), "workspace");
        assert_eq!(effective_profile("ops", &file), "ops");
    }

    #[test]
    fn resolve_token_from_args() {
        let args = RegionsArgs {
            command: RegionsCommand::Current,
            api_url: None,
            api_token: Some("explicit-token".to_string()),
            config: None,
            profile: "default".to_string(),
            json: false,
        };
        let result = resolve_token(&args).unwrap();
        assert_eq!(result, Some("explicit-token".to_string()));
    }

    #[test]
    fn check_source_returns_dash_for_inactive_source() {
        assert_eq!(check_source("env", "file", "us-east"), "-");
    }

    #[test]
    fn check_source_active_includes_value() {
        let result = check_source("env", "env", "ap-south");
        assert!(result.contains("ap-south"));
        assert!(result.contains("active"));
    }

    #[test]
    fn validate_list_filters_rejects_conflicting_enabled_and_disabled() {
        let error = validate_list_filters(&RegionListFilters {
            enabled: true,
            disabled: true,
            group: None,
            sovereignty_class: None,
        })
        .expect_err("conflicting filters should error");
        assert!(error.to_string().contains("--enabled and --disabled"));
    }

    #[test]
    fn apply_filters_supports_enabled_group_and_sovereignty_class() {
        let mut regions = vec![
            RegionListItem {
                region_key: "eu-west".to_string(),
                display_name: "EU West".to_string(),
                sovereignty_class: "eu_sovereign".to_string(),
                lifecycle_state: "active".to_string(),
                api_endpoint: None,
                console_endpoint: None,
                family_memberships: Vec::new(),
                primary_region_group_key: Some("eu".to_string()),
                default_currency: None,
                enabled_region: Some("eu-west".to_string()),
                visible_region: Some("eu-west".to_string()),
                default_region: None,
                requested_region: None,
                resource_home_region: Some("eu-west".to_string()),
            },
            RegionListItem {
                region_key: "us-east".to_string(),
                display_name: "US East".to_string(),
                sovereignty_class: "standard".to_string(),
                lifecycle_state: "disabled".to_string(),
                api_endpoint: None,
                console_endpoint: None,
                family_memberships: Vec::new(),
                primary_region_group_key: Some("us".to_string()),
                default_currency: None,
                enabled_region: None,
                visible_region: Some("us-east".to_string()),
                default_region: None,
                requested_region: None,
                resource_home_region: Some("us-east".to_string()),
            },
        ];

        apply_filters(
            &mut regions,
            &RegionListFilters {
                enabled: true,
                disabled: false,
                group: Some("eu".to_string()),
                sovereignty_class: Some("eu_sovereign".to_string()),
            },
        );

        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].region_key, "eu-west");
    }

    #[test]
    fn requested_region_scope_global_when_region_is_global_or_missing() {
        assert_eq!(
            RequestedRegionScope::from_region(Some("global")).as_str(),
            "global"
        );
        assert_eq!(RequestedRegionScope::from_region(None).as_str(), "global");
        assert_eq!(
            RequestedRegionScope::from_region(Some("eu-west")).as_str(),
            "regional"
        );
    }

    #[test]
    fn resolve_region_context_prefers_env_over_profile_and_legacy_defaults() {
        let _lock = crate::config::test_env_lock().lock().expect("env lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "profile: workspace\ndefault_region: global\nprofiles:\n  workspace:\n    default_region: eu-west\n",
        )
        .expect("seed config");
        std::env::set_var("VERDICTAN_REGION", "us-east");

        let context = resolve_region_context(&RegionsArgs {
            command: RegionsCommand::Current,
            config: Some(config_path),
            api_url: None,
            api_token: None,
            profile: "default".to_string(),
            json: false,
        })
        .expect("resolve context");

        assert_eq!(context.effective_profile, "workspace");
        assert_eq!(context.default_region.as_deref(), Some("eu-west"));
        assert_eq!(context.requested_region.as_deref(), Some("us-east"));
        assert_eq!(
            context.requested_region_source.as_deref(),
            Some("VERDICTAN_REGION env")
        );

        std::env::remove_var("VERDICTAN_REGION");
    }
}
