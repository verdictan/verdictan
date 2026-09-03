// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// MCP tool: regions_list
use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use super::ToolContext;
use crate::error::CliError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegionCatalogScope {
    Public,
    Organization,
    Merged,
}

#[derive(Debug, Clone)]
pub(crate) struct NormalizedRegion {
    pub(crate) region_key: String,
    pub(crate) display_name: String,
    pub(crate) sovereignty_class: String,
    pub(crate) lifecycle_state: String,
    pub(crate) api_endpoint: Option<String>,
    pub(crate) console_endpoint: Option<String>,
    pub(crate) family_memberships: Vec<String>,
    pub(crate) primary_region_group_key: Option<String>,
    pub(crate) default_currency: Option<String>,
    pub(crate) available_to_org: bool,
    pub(crate) enabled_region: Option<String>,
    pub(crate) visible_region: Option<String>,
    pub(crate) resource_home_region: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublicRegionCatalog {
    regions: Vec<PublicRegionRecord>,
}

#[derive(Debug, Deserialize)]
struct PublicRegionRecord {
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

#[derive(Debug, Deserialize)]
struct OrganizationRegionCatalog {
    #[serde(default)]
    cells: Vec<OrganizationRegionRecord>,
}

#[derive(Debug, Deserialize)]
struct OrganizationRegionRecord {
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

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "regions_list",
        "description": "List available regions, sovereignty classes, group keys, and org availability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "enum": ["merged", "public", "organization"],
                    "description": "Which region source to use."
                },
                "enabled": {
                    "type": "boolean",
                    "description": "Return only active/enabled regions."
                },
                "disabled": {
                    "type": "boolean",
                    "description": "Return only regions that are not active or are disabled."
                },
                "group": {
                    "type": "string",
                    "description": "Filter by primary region group key."
                },
                "sovereignty_class": {
                    "type": "string",
                    "description": "Filter by sovereignty class."
                },
                "limit": {
                    "type": "integer",
                    "description": "Optional max number of regions to return."
                }
            }
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let scope = scope_argument(arguments)?;
    let filters = filters_from_arguments(arguments)?;
    let limit = limit_argument(arguments)?;

    tracing::debug!(
        session_id = %ctx.session_id,
        scope = %scope.as_str(),
        enabled = filters.enabled,
        disabled = filters.disabled,
        "listing regions via MCP"
    );

    let mut regions = load_regions(ctx, scope).await?;
    apply_filters(&mut regions, &filters);
    if let Some(limit) = limit {
        regions.truncate(limit as usize);
    }

    Ok(serde_json::json!({
        "scope": scope.as_str(),
        "regions": regions.iter().map(region_to_value).collect::<Vec<_>>(),
        "total_count": regions.len(),
    }))
}

pub(crate) async fn load_regions(
    ctx: &ToolContext<'_>,
    scope: RegionCatalogScope,
) -> Result<Vec<NormalizedRegion>, CliError> {
    match scope {
        RegionCatalogScope::Public => fetch_public_regions(ctx).await,
        RegionCatalogScope::Organization => fetch_organization_regions(ctx).await,
        RegionCatalogScope::Merged => merge_regions(
            fetch_public_regions(ctx).await?,
            fetch_organization_regions(ctx).await?,
        ),
    }
}

pub(crate) fn region_to_value(region: &NormalizedRegion) -> Value {
    serde_json::json!({
        "region_key": region.region_key,
        "display_name": region.display_name,
        "sovereignty_class": region.sovereignty_class,
        "lifecycle_state": region.lifecycle_state,
        "api_endpoint": region.api_endpoint,
        "console_endpoint": region.console_endpoint,
        "family_memberships": region.family_memberships,
        "primary_region_group_key": region.primary_region_group_key,
        "default_currency": region.default_currency,
        "available_to_org": region.available_to_org,
        "enabled_region": region.enabled_region,
        "visible_region": region.visible_region,
        "resource_home_region": region.resource_home_region,
    })
}

fn merge_regions(
    public_regions: Vec<NormalizedRegion>,
    organization_regions: Vec<NormalizedRegion>,
) -> Result<Vec<NormalizedRegion>, CliError> {
    let mut merged = BTreeMap::<String, NormalizedRegion>::new();

    for region in public_regions {
        merged.insert(region.region_key.clone(), region);
    }

    for org_region in organization_regions {
        merged
            .entry(org_region.region_key.clone())
            .and_modify(|existing| {
                existing.display_name = org_region.display_name.clone();
                existing.sovereignty_class = org_region.sovereignty_class.clone();
                existing.lifecycle_state = org_region.lifecycle_state.clone();
                existing.api_endpoint = org_region
                    .api_endpoint
                    .clone()
                    .or_else(|| existing.api_endpoint.clone());
                existing.console_endpoint = org_region
                    .console_endpoint
                    .clone()
                    .or_else(|| existing.console_endpoint.clone());
                if !org_region.family_memberships.is_empty() {
                    existing.family_memberships = org_region.family_memberships.clone();
                }
                existing.primary_region_group_key = org_region.primary_region_group_key.clone();
                existing.default_currency = org_region.default_currency.clone();
                existing.available_to_org = true;
                existing.enabled_region = org_region.enabled_region.clone();
                existing.visible_region = org_region.visible_region.clone();
                existing.resource_home_region = org_region.resource_home_region.clone();
            })
            .or_insert(org_region);
    }

    Ok(merged.into_values().collect())
}

async fn fetch_public_regions(ctx: &ToolContext<'_>) -> Result<Vec<NormalizedRegion>, CliError> {
    let response = ctx.client.get_json_value("/v1/regions").await?;
    let catalog: PublicRegionCatalog = serde_json::from_value(response).map_err(|error| {
        CliError::internal(format!(
            "regions_list failed to parse public region catalog: {error}"
        ))
    })?;

    Ok(catalog
        .regions
        .into_iter()
        .map(|region| NormalizedRegion {
            enabled_region: matches!(region.lifecycle_state.as_str(), "active")
                .then(|| region.region_key.clone()),
            visible_region: Some(region.region_key.clone()),
            resource_home_region: Some(region.region_key.clone()),
            region_key: region.region_key,
            display_name: region.display_name,
            sovereignty_class: region.sovereignty_class,
            lifecycle_state: region.lifecycle_state,
            api_endpoint: region.api_endpoint,
            console_endpoint: region.console_endpoint,
            family_memberships: region.family_memberships,
            primary_region_group_key: None,
            default_currency: region.default_currency,
            available_to_org: false,
        })
        .collect())
}

async fn fetch_organization_regions(
    ctx: &ToolContext<'_>,
) -> Result<Vec<NormalizedRegion>, CliError> {
    let response = ctx
        .client
        .get_json_value("/v1/organization/regions")
        .await?;
    let catalog: OrganizationRegionCatalog = serde_json::from_value(response).map_err(|error| {
        CliError::internal(format!(
            "regions_list failed to parse organization region catalog: {error}"
        ))
    })?;

    Ok(catalog
        .cells
        .into_iter()
        .map(|region| {
            let family_memberships = region
                .family_bindings
                .into_iter()
                .map(|binding| binding.family_key)
                .collect::<Vec<_>>();
            let default_currency = region.default_currency.trim();

            NormalizedRegion {
                enabled_region: matches!(region.status.as_str(), "active")
                    .then(|| region.region_key.clone()),
                visible_region: Some(region.region_key.clone()),
                resource_home_region: Some(region.region_key.clone()),
                region_key: region.region_key,
                display_name: region.name,
                sovereignty_class: region.sovereignty_class,
                lifecycle_state: region.status,
                api_endpoint: region.customer_api_origin,
                console_endpoint: region.customer_console_origin,
                family_memberships,
                primary_region_group_key: Some(region.primary_region_group_key),
                default_currency: (!default_currency.is_empty())
                    .then(|| default_currency.to_string()),
                available_to_org: true,
            }
        })
        .collect())
}

#[derive(Debug, Default)]
struct RegionFilters {
    enabled: bool,
    disabled: bool,
    group: Option<String>,
    sovereignty_class: Option<String>,
}

fn filters_from_arguments(arguments: &Value) -> Result<RegionFilters, CliError> {
    let enabled = boolean_argument(arguments, "enabled")?.unwrap_or(false);
    let disabled = boolean_argument(arguments, "disabled")?.unwrap_or(false);
    if enabled && disabled {
        return Err(CliError::user(
            "regions_list cannot combine 'enabled' and 'disabled'",
        ));
    }

    Ok(RegionFilters {
        enabled,
        disabled,
        group: string_argument(arguments, &["group", "primary_region_group_key"])?,
        sovereignty_class: string_argument(arguments, &["sovereignty_class"])?,
    })
}

fn apply_filters(regions: &mut Vec<NormalizedRegion>, filters: &RegionFilters) {
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

fn scope_argument(arguments: &Value) -> Result<RegionCatalogScope, CliError> {
    let Some(value) = arguments.get("scope") else {
        return Ok(RegionCatalogScope::Merged);
    };
    let scope = value
        .as_str()
        .ok_or_else(|| CliError::user("regions_list 'scope' must be a string"))?;
    match scope.trim() {
        "" | "merged" => Ok(RegionCatalogScope::Merged),
        "public" => Ok(RegionCatalogScope::Public),
        "organization" => Ok(RegionCatalogScope::Organization),
        other => Err(CliError::user(format!(
            "regions_list 'scope' must be one of: merged, public, organization (got '{other}')"
        ))),
    }
}

fn limit_argument(arguments: &Value) -> Result<Option<u64>, CliError> {
    let Some(value) = arguments.get("limit") else {
        return Ok(None);
    };
    let limit = value
        .as_u64()
        .ok_or_else(|| CliError::user("regions_list 'limit' must be an integer"))?;
    Ok(Some(limit))
}

fn string_argument(arguments: &Value, keys: &[&str]) -> Result<Option<String>, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let text = value
                .as_str()
                .ok_or_else(|| CliError::user(format!("regions_list '{key}' must be a string")))?;
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
    }
    Ok(None)
}

fn boolean_argument(arguments: &Value, key: &str) -> Result<Option<bool>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let flag = value
        .as_bool()
        .ok_or_else(|| CliError::user(format!("regions_list '{key}' must be a boolean")))?;
    Ok(Some(flag))
}

impl RegionCatalogScope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Organization => "organization",
            Self::Merged => "merged",
        }
    }
}
