// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// MCP tool: region_get
use serde_json::Value;

use super::regions_list::{load_regions, region_to_value, RegionCatalogScope};
use super::ToolContext;
use crate::error::CliError;

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "region_get",
        "description": "Get one region's merged public and organization metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "region_key": {
                    "type": "string",
                    "description": "Exact region key."
                },
                "scope": {
                    "type": "string",
                    "enum": ["merged", "public", "organization"],
                    "description": "Which region source to use."
                }
            },
            "required": ["region_key"]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let region_key = required_string_argument(arguments, &["region_key", "id"])?;
    let scope = scope_argument(arguments)?;

    tracing::debug!(
        session_id = %ctx.session_id,
        region_key = %region_key,
        scope = %scope.as_str(),
        "fetching region via MCP"
    );

    let regions = load_regions(ctx, scope).await?;
    let region = regions
        .iter()
        .find(|candidate| candidate.region_key == region_key)
        .ok_or_else(|| {
            CliError::user(format!("region_get could not find region '{region_key}'"))
        })?;

    Ok(region_to_value(region))
}

fn required_string_argument(arguments: &Value, keys: &[&str]) -> Result<String, CliError> {
    for key in keys {
        if let Some(value) = arguments.get(*key) {
            let text = value
                .as_str()
                .ok_or_else(|| CliError::user(format!("region_get '{key}' must be a string")))?;
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    Err(CliError::user("region_get requires 'region_key'"))
}

fn scope_argument(arguments: &Value) -> Result<RegionCatalogScope, CliError> {
    let Some(value) = arguments.get("scope") else {
        return Ok(RegionCatalogScope::Merged);
    };
    let scope = value
        .as_str()
        .ok_or_else(|| CliError::user("region_get 'scope' must be a string"))?;
    match scope.trim() {
        "" | "merged" => Ok(RegionCatalogScope::Merged),
        "public" => Ok(RegionCatalogScope::Public),
        "organization" => Ok(RegionCatalogScope::Organization),
        other => Err(CliError::user(format!(
            "region_get 'scope' must be one of: merged, public, organization (got '{other}')"
        ))),
    }
}
