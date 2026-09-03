// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::api::AsyncApiClient;
use crate::error::CliError;
use crate::gateway::{
    cache::{
        l1::{
            hash_context_query, shared_l1_cache, ContextCacheAuthorization, ContextPlanItem,
            ContextPlanL1Cache,
        },
        l2::{shared_l2_cache, ContextPlanL2Cache},
    },
    crdt::{ContextEntryView, LocalReadScope},
};
use crate::mcp::local_context_runtime::{
    shared_local_context_runtime_registry, LocalContextSessionHandle,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedSessionScope {
    pub team_id: Option<String>,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub working_directory: Option<String>,
    pub used_stored_scope: bool,
}

pub fn local_context_session_handle(session_id: &str) -> LocalContextSessionHandle {
    shared_local_context_runtime_registry().session(session_id.to_string())
}

pub fn resolve_session_scope(
    session_id: &str,
    explicit_team_id: Option<&str>,
    explicit_repo: Option<&str>,
    explicit_branch: Option<&str>,
) -> ResolvedSessionScope {
    let stored = local_context_session_handle(session_id).scope();
    ResolvedSessionScope {
        team_id: explicit_team_id
            .map(str::to_string)
            .or_else(|| stored.as_ref().and_then(|scope| scope.team_id.clone())),
        repo: explicit_repo
            .map(str::to_string)
            .or_else(|| stored.as_ref().and_then(|scope| scope.repo.clone())),
        branch: explicit_branch
            .map(str::to_string)
            .or_else(|| stored.as_ref().and_then(|scope| scope.branch.clone())),
        commit: stored.as_ref().and_then(|scope| scope.commit.clone()),
        working_directory: stored.and_then(|scope| scope.working_directory),
        used_stored_scope: explicit_team_id.is_none()
            || explicit_repo.is_none()
            || explicit_branch.is_none(),
    }
}

pub fn local_entry_value(view: &ContextEntryView) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("id".to_string(), Value::String(view.entry_id.clone()));
    for (key, value) in &view.fields {
        object.insert(key.clone(), value.clone());
    }
    Value::Object(object)
}

#[derive(Clone, Copy)]
pub struct ContextRecallConfig<'a> {
    pub session_id: &'a str,
    pub max_results: usize,
    pub confidence_threshold: Option<f64>,
    pub l1_cache: &'static ContextPlanL1Cache,
    pub l2_cache: &'static ContextPlanL2Cache,
    pub allow_crdt_fallback: bool,
    pub include_disputed: bool,
    pub team_id: Option<&'a str>,
    pub repo: Option<&'a str>,
    pub branch: Option<&'a str>,
    pub cache_authorization: Option<&'a ContextCacheAuthorization>,
}

impl<'a> ContextRecallConfig<'a> {
    pub fn new(session_id: &'a str) -> Self {
        Self {
            session_id,
            max_results: 20,
            confidence_threshold: None,
            l1_cache: shared_l1_cache(),
            l2_cache: shared_l2_cache(),
            allow_crdt_fallback: true,
            include_disputed: false,
            team_id: None,
            repo: None,
            branch: None,
            cache_authorization: None,
        }
    }
}

pub async fn authorize_context_cache_scope(
    client: &AsyncApiClient,
    requested_team_id: Option<&str>,
) -> Result<ContextCacheAuthorization, CliError> {
    authorize_context_cache_scope_for_permission(client, requested_team_id, "history:read").await
}

pub async fn authorize_context_cache_mutation_scope(
    client: &AsyncApiClient,
    requested_team_id: Option<&str>,
) -> Result<ContextCacheAuthorization, CliError> {
    authorize_context_cache_scope_for_permission(client, requested_team_id, "history:write").await
}

async fn authorize_context_cache_scope_for_permission(
    client: &AsyncApiClient,
    requested_team_id: Option<&str>,
    required_permission: &str,
) -> Result<ContextCacheAuthorization, CliError> {
    let identity = client.get_json_value("/v1/whoami").await?;
    let organization_id = required_identity_string(&identity, "org_id")?;
    let _user_id = required_identity_string(&identity, "user_id")?;
    let permissions = normalized_string_array(identity.get("permissions"));
    if !permissions
        .iter()
        .any(|permission| permission == required_permission)
    {
        return Err(CliError::auth(format!(
            "MCP context cache access requires authoritative {required_permission} permission"
        )));
    }

    let team_ids = normalized_string_array(identity.get("team_ids"));
    let team_id = match requested_team_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(team_id) => {
            if !team_ids.iter().any(|candidate| candidate == team_id) {
                return Err(CliError::auth(
                    "MCP context cache access denied for the requested team",
                ));
            }
            Some(team_id.to_string())
        }
        None if team_ids.len() == 1 => team_ids.first().cloned(),
        None => None,
    };

    Ok(ContextCacheAuthorization::new(
        organization_id,
        team_id,
        authorization_version(&identity, &team_ids, &permissions),
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalContextRecallBackend {
    L1Cache,
    L2BloomNegative,
    LocalCrdt,
}

impl LocalContextRecallBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L1Cache => "l1_cache",
            Self::L2BloomNegative => "l2_bloom_negative",
            Self::LocalCrdt => "local_crdt",
        }
    }

    pub fn note(self) -> &'static str {
        match self {
            Self::L1Cache => "Served from the L1 in-process context plan cache.",
            Self::L2BloomNegative => {
                "L2 Bloom filter indicates this topic was never discussed in this partition."
            }
            Self::LocalCrdt => {
                "Served from the local gateway CRDT replica for the current MCP session."
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ContextRecallEntry {
    pub item: ContextPlanItem,
    pub document: Value,
}

#[derive(Clone, Debug)]
pub struct ContextRecallResult {
    pub backend: LocalContextRecallBackend,
    pub scope: ResolvedSessionScope,
    pub include_disputed: bool,
    pub entries: Vec<ContextRecallEntry>,
}

pub async fn recall_context(
    query: &str,
    config: &ContextRecallConfig<'_>,
) -> Option<ContextRecallResult> {
    let resolved_scope = resolve_session_scope(
        config.session_id,
        config.team_id,
        config.repo,
        config.branch,
    );
    if resolved_scope.repo.is_none()
        && resolved_scope.branch.is_none()
        && resolved_scope.team_id.is_none()
    {
        return None;
    }

    let max_results = config.max_results.max(1);

    if let (Some(authorization), Some(repo_val), Some(branch_val)) = (
        config.cache_authorization,
        resolved_scope.repo.as_deref(),
        resolved_scope.branch.as_deref(),
    ) {
        let query_hash = hash_context_query(query);
        if let Some(plan) = config
            .l1_cache
            .get(authorization, repo_val, branch_val, query_hash)
        {
            let entries = plan
                .items
                .iter()
                .take(max_results)
                .cloned()
                .map(|item| ContextRecallEntry {
                    document: context_plan_item_document(&item),
                    item,
                })
                .collect();
            tracing::debug!(
                session_id = config.session_id,
                query,
                hit_count = max_results.min(plan.items.len()),
                "local context recall L1 cache hit"
            );
            return Some(ContextRecallResult {
                backend: LocalContextRecallBackend::L1Cache,
                scope: resolved_scope,
                include_disputed: config.include_disputed,
                entries,
            });
        }

        if !config
            .l2_cache
            .topic_might_exist(repo_val, branch_val, query)
        {
            tracing::debug!(
                session_id = config.session_id,
                query,
                repo = repo_val,
                branch = branch_val,
                "local context recall L2 bloom negative"
            );
            return Some(ContextRecallResult {
                backend: LocalContextRecallBackend::L2BloomNegative,
                scope: resolved_scope,
                include_disputed: config.include_disputed,
                entries: Vec::new(),
            });
        }
    }

    if !config.allow_crdt_fallback {
        return None;
    }

    let handle = local_context_session_handle(config.session_id);
    let driver = handle.crdt_sync_driver()?;
    let replica = driver.state();
    let scope = LocalReadScope::scoped(
        resolved_scope.repo.as_deref(),
        resolved_scope.branch.as_deref(),
    );
    let mut results = replica.read().await.local_search(query, &scope, usize::MAX);
    if let Some(expected_team_id) = resolved_scope.team_id.as_deref() {
        results.retain(|view| owner_team_matches(view, expected_team_id));
    }
    if !config.include_disputed {
        results.retain(|view| !is_disputed_or_flagged(view));
    }
    if let Some(threshold) = config.confidence_threshold {
        results.retain(|view| confidence_meets_threshold(view, threshold));
    }
    results.truncate(max_results);

    let entries = results
        .into_iter()
        .filter_map(|view| {
            let document = local_entry_value(&view);
            let item = context_plan_item_from_document(&document)?;
            Some(ContextRecallEntry { item, document })
        })
        .collect();

    Some(ContextRecallResult {
        backend: LocalContextRecallBackend::LocalCrdt,
        scope: resolved_scope,
        include_disputed: config.include_disputed,
        entries,
    })
}

fn owner_team_matches(view: &ContextEntryView, expected_team_id: &str) -> bool {
    view.field_str("owner_team_id")
        .map(|value| value == expected_team_id)
        .unwrap_or(false)
}

fn is_disputed_or_flagged(view: &ContextEntryView) -> bool {
    matches!(
        view.field_str("verification_status"),
        Some("flagged" | "disputed" | "conflict_pending")
    )
}

fn confidence_meets_threshold(view: &ContextEntryView, threshold: f64) -> bool {
    view.fields
        .get("confidence_score")
        .and_then(Value::as_f64)
        .is_none_or(|score| score >= threshold)
}

fn context_plan_item_document(item: &ContextPlanItem) -> Value {
    serde_json::json!({
        "id": item.item_id,
        "content": item.content,
        "token_estimate": item.token_estimate,
        "citation_required": item.citation_required,
        "source_kind": item.source_kind,
        "title": Value::Null,
        "summary": Value::Null,
        "tags": [],
    })
}

fn context_plan_item_from_document(document: &Value) -> Option<ContextPlanItem> {
    let item_id = document
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)?;
    let content = document
        .get("content")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)?;

    Some(ContextPlanItem {
        organization_id: String::new(),
        team_id: None,
        authorization_version: String::new(),
        item_id,
        content,
        token_estimate: document
            .get("token_estimate")
            .and_then(Value::as_u64)
            .map(|value| value.min(u32::MAX as u64) as u32)
            .unwrap_or(0),
        citation_required: document
            .get("citation_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        source_kind: document
            .get("source_kind")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
    })
}

fn required_identity_string(identity: &Value, key: &str) -> Result<String, CliError> {
    identity
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            CliError::auth(format!(
                "authoritative identity response is missing required {key}"
            ))
        })
}

fn normalized_string_array(value: Option<&Value>) -> Vec<String> {
    let mut values = value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn authorization_version(identity: &Value, team_ids: &[String], permissions: &[String]) -> String {
    if let Some(version) = identity
        .get("authz_version")
        .and_then(|value| {
            value
                .as_i64()
                .map(|value| value.to_string())
                .or_else(|| value.as_str().map(str::to_string))
        })
        .filter(|value| !value.trim().is_empty())
    {
        return version;
    }

    let mut capabilities = normalized_string_array(identity.get("capabilities"));
    let mut resolved_roles = identity
        .get("resolved_roles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(Value::to_string)
        .collect::<Vec<_>>();
    capabilities.sort();
    resolved_roles.sort();
    let snapshot = serde_json::json!({
        "org_id": identity.get("org_id"),
        "user_id": identity.get("user_id"),
        "role": identity.get("role"),
        "auth_method": identity.get("auth_method"),
        "team_ids": team_ids,
        "permissions": permissions,
        "capabilities": capabilities,
        "resolved_roles": resolved_roles,
    });
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(snapshot.to_string()))
    )
}
