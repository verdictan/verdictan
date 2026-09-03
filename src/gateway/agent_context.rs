// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    context_packs::{shared_context_pack_cache, ContextPackCacheKey},
    context_recall,
    session::GatewaySessionContext,
    task_novelty::TaskNoveltyRequest,
    token_estimation,
};

const LOCAL_CONTEXT_RECALL_LIMIT: u64 = 20;

#[derive(Clone)]
pub struct AgentContextService {
    client: reqwest::Client,
    gateway_client: Option<reqwest::Client>,
    api_base: String,
    timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeContextConfig {
    pub allow_working_context: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContextTokenBreakdown {
    pub max_context_tokens: u32,
    pub estimated_tokens: u32,
    pub injected_tokens: u32,
    pub working_context_tokens: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct SelectedContextItemTelemetry {
    pub item_id: String,
    pub item_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_history_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hierarchy_lane: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_confidence_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_verification_status: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ContextSelectionTelemetry {
    pub plan_hash: String,
    pub context_policy_version: i64,
    pub selected_item_ids: Vec<String>,
    pub selected_items: Vec<SelectedContextItemTelemetry>,
    pub selected_hierarchy_lanes: Vec<String>,
    pub selected_receipt_ids: Vec<String>,
    pub citation_required_count: u32,
    pub tokens: ContextTokenBreakdown,
    pub pack_hash: Option<String>,
    /// Version-locked manifest hash including KB identity.
    pub manifest_hash: Option<String>,
    /// Ranking policy version used for this plan.
    pub ranking_policy_version: Option<String>,
    /// Visibility/entitlement digest used for KB recall scoping.
    pub visibility_digest: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct AppliedAgentContext {
    pub block: String,
    pub telemetry: ContextSelectionTelemetry,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResolveContextRequest {
    agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    error_signature_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    file_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    symbols: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    command_names: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    refresh_frozen: bool,
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GatewayResolveContextRequest {
    org_id: String,
    #[serde(flatten)]
    inner: ResolveContextRequest,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ContextItemType {
    WorkingContext,
    #[serde(other)]
    Other,
}

impl ContextItemType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::WorkingContext => "working_context",
            Self::Other => "other",
        }
    }

    fn allowed(self, runtime: RuntimeContextConfig) -> bool {
        match self {
            Self::Other => false,
            Self::WorkingContext => runtime.allow_working_context,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct AgentContextItem {
    item_id: String,
    item_type: ContextItemType,
    /// Sentence span id for sentence-level citation.
    #[serde(default)]
    _sentence_id: Option<String>,
    /// Sentence index within the unit.
    #[serde(default)]
    _sentence_index: Option<i32>,
    /// Start character offset of the sentence span.
    #[serde(default)]
    _start_offset: Option<i32>,
    /// End character offset of the sentence span.
    #[serde(default)]
    _end_offset: Option<i32>,
    source_history_session_id: Option<String>,
    content: String,
    token_estimate: u32,
    citation_required: bool,
    /// Request-aware BM25 rank score.
    #[serde(default)]
    _rank_score: Option<f64>,
    #[serde(default)]
    hierarchy_lane: Option<String>,
    #[serde(default)]
    receipt_id: Option<String>,
    #[serde(default)]
    receipt_confidence_score: Option<f64>,
    #[serde(default)]
    receipt_verification_status: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AgentContextPlan {
    plan_hash: String,
    context_policy_version: i64,
    max_context_tokens: u32,
    #[serde(rename = "estimated_tokens")]
    _estimated_tokens: u32,
    items: Vec<AgentContextItem>,
    #[serde(default)]
    _working_context_tokens: u32,
    #[serde(default)]
    pack_hash: Option<String>,
    /// Version-locked manifest hash including KB identity.
    #[serde(default)]
    manifest_hash: Option<String>,
    /// Ranking policy version used for this plan.
    #[serde(default)]
    ranking_policy_version: Option<String>,
    /// Visibility/entitlement digest used for KB recall scoping.
    #[serde(default)]
    visibility_digest: Option<String>,
}

impl AgentContextService {
    pub fn new(
        client: reqwest::Client,
        gateway_client: Option<reqwest::Client>,
        api_base: String,
        timeout_ms: u64,
    ) -> Self {
        Self {
            client,
            gateway_client,
            api_base,
            timeout_ms,
        }
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub async fn resolve_context(
        &self,
        session: &GatewaySessionContext,
        gateway_id: Option<&str>,
        request_text: Option<&str>,
        runtime: RuntimeContextConfig,
        novelty_request: Option<&TaskNoveltyRequest>,
    ) -> anyhow::Result<Option<AppliedAgentContext>> {
        if !runtime.allow_working_context {
            return Ok(None);
        }

        let Some(agent_id) = normalize_text(session.agent_id.as_deref()) else {
            return Ok(None);
        };

        let request = ResolveContextRequest {
            agent_id,
            gateway_id: normalize_text(gateway_id),
            team_id: normalize_text(session.team_id.as_deref()),
            user_id: normalize_text(session.user_id.as_deref()),
            session_id: normalize_text(Some(session.session_id.as_str())),
            conversation_id: normalize_text(session.conversation_id.as_deref()),
            request_text: normalize_text(request_text),
            git_repo: normalize_text(
                session
                    .git_context
                    .as_ref()
                    .and_then(|context| context.repo.as_deref()),
            ),
            git_branch: normalize_text(
                session
                    .git_context
                    .as_ref()
                    .and_then(|context| context.branch.as_deref()),
            ),
            git_commit: normalize_text(
                session
                    .git_context
                    .as_ref()
                    .and_then(|context| context.commit.as_deref()),
            ),
            error_signature_hashes: novelty_request
                .map(|request| request.error_signature_hashes.clone())
                .unwrap_or_default(),
            file_paths: novelty_request
                .map(|request| request.file_paths.clone())
                .unwrap_or_default(),
            symbols: novelty_request
                .map(|request| request.symbols.clone())
                .unwrap_or_default(),
            package_scope: novelty_request.and_then(|request| request.package_scope.clone()),
            command_names: novelty_request
                .map(|request| request.command_names.clone())
                .unwrap_or_default(),
            refresh_frozen: false,
        };
        let prefer_remote_pack = request.git_repo.is_some() && request.git_branch.is_some();

        if prefer_remote_pack {
            let plan = self.fetch_context_plan(session, &request).await?;
            if let Some(applied) = build_or_reuse_applied_context(&request, plan, runtime) {
                return Ok(Some(applied));
            }
        }

        if let Some(query) = request.request_text.as_deref() {
            let local_recall_config = context_recall::ContextRecallConfig {
                session_id: session.session_id.as_str(),
                max_results: LOCAL_CONTEXT_RECALL_LIMIT as usize,
                include_disputed: false,
                team_id: request.team_id.as_deref(),
                repo: request.git_repo.as_deref(),
                branch: request.git_branch.as_deref(),
                ..context_recall::ContextRecallConfig::new(session.session_id.as_str())
            };
            if let Some(local_recall) =
                context_recall::recall_context(query, &local_recall_config).await
            {
                if let Some(plan) = build_local_context_plan(query, &local_recall) {
                    if let Some(applied) = build_applied_context(plan, runtime) {
                        tracing::debug!(
                            session_id = %session.session_id,
                            query = %query,
                            backend = local_recall.backend.as_str(),
                            item_count = local_recall.entries.len(),
                            "resolved agent context from shared local recall"
                        );
                        return Ok(Some(applied));
                    }
                }
            }
        }

        if prefer_remote_pack {
            return Ok(None);
        }

        let plan = self.fetch_context_plan(session, &request).await?;
        Ok(build_or_reuse_applied_context(&request, plan, runtime))
    }

    async fn fetch_context_plan(
        &self,
        session: &GatewaySessionContext,
        request: &ResolveContextRequest,
    ) -> anyhow::Result<AgentContextPlan> {
        let org_id = normalize_text(session._org_id.as_deref());
        let (client, url, body) = match (&self.gateway_client, org_id.as_deref()) {
            (Some(client), Some(org_id)) => (
                client,
                self.join_url("/v1/gateway/agent-context/resolve"),
                serde_json::to_value(GatewayResolveContextRequest {
                    org_id: org_id.to_string(),
                    inner: request.clone(),
                })?,
            ),
            (Some(_), None) => {
                anyhow::bail!("gateway agent context resolution missing org_id")
            }
            (None, _) => (
                &self.client,
                self.join_url("/v1/agent-context/resolve"),
                serde_json::to_value(request)?,
            ),
        };

        let response = client
            .post(url)
            .json(&body)
            .send()
            .await
            .context("agent context request failed")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            // ADR-007: classify machine route errors for structured diagnostics.
            anyhow::bail!(
                "{}",
                super::machine_route_error::classify_and_format(
                    "agent-context/resolve",
                    status,
                    &text,
                )
            );
        }

        let plan = response
            .json::<AgentContextPlan>()
            .await
            .context("failed to decode agent context plan")?;

        Ok(plan)
    }

    pub fn inject_into_chat_request(
        request: &mut serde_json::Value,
        applied: &AppliedAgentContext,
    ) -> bool {
        let Some(messages) = request
            .get_mut("messages")
            .and_then(|value| value.as_array_mut())
        else {
            return false;
        };
        if applied.block.trim().is_empty() {
            return false;
        }
        messages.insert(
            0,
            serde_json::json!({
                "role": "system",
                "content": applied.block,
                "_verdictan_recalled": true,
            }),
        );
        true
    }

    pub fn inject_into_responses_request(
        request: &mut serde_json::Value,
        applied: &AppliedAgentContext,
    ) -> bool {
        if applied.block.trim().is_empty() {
            return false;
        }

        let Some(input) = request.get_mut("input") else {
            request["input"] = serde_json::json!([{
                "role": "system",
                "content": applied.block,
                "_verdictan_recalled": true,
            }]);
            return true;
        };

        if let Some(existing) = input.as_str() {
            *input = serde_json::json!([
                {
                    "role": "system",
                    "content": applied.block,
                    "_verdictan_recalled": true,
                },
                existing,
            ]);
            return true;
        }

        let Some(items) = input.as_array_mut() else {
            return false;
        };
        items.insert(
            0,
            serde_json::json!({
                "role": "system",
                "content": applied.block,
                "_verdictan_recalled": true,
            }),
        );
        true
    }

    /// Execute a context flush via the API's flush endpoint.
    /// Called by the pre-compression flush orchestrator when the assembled prompt
    /// exceeds the provider token budget.
    pub async fn execute_context_flush<R: serde::Serialize>(
        &self,
        request: &R,
    ) -> anyhow::Result<super::context_flush::FlushResponse> {
        let (client, url) = match &self.gateway_client {
            Some(client) => (client, self.join_url("/v1/gateway/context-flush")),
            None => (&self.client, self.join_url("/v1/context-flush")),
        };

        let response = client
            .post(url)
            .json(request)
            .send()
            .await
            .context("context flush request failed")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            // ADR-007: classify machine route errors for structured diagnostics.
            anyhow::bail!(
                "{}",
                super::machine_route_error::classify_and_format("context-flush", status, &text,)
            );
        }

        response
            .json()
            .await
            .context("failed to decode context flush response")
    }

    fn join_url(&self, path: &str) -> String {
        let base = self.api_base.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{base}/{path}")
    }
}

fn build_or_reuse_applied_context(
    request: &ResolveContextRequest,
    plan: AgentContextPlan,
    runtime: RuntimeContextConfig,
) -> Option<AppliedAgentContext> {
    let cache_key = context_pack_cache_key(request, &plan);
    if let Some(cache_key) = cache_key.as_ref() {
        if let Ok(mut cache) = shared_context_pack_cache().lock() {
            if let Some(applied) = cache.get(cache_key) {
                return Some(applied);
            }
        }
    }

    let applied = build_applied_context(plan, runtime)?;
    if let Some(cache_key) = cache_key {
        if let Ok(mut cache) = shared_context_pack_cache().lock() {
            cache.insert(cache_key, applied.clone());
        }
    }
    Some(applied)
}

fn context_pack_cache_key(
    request: &ResolveContextRequest,
    plan: &AgentContextPlan,
) -> Option<ContextPackCacheKey> {
    Some(ContextPackCacheKey {
        team_id: request.team_id.clone(),
        agent_id: request.agent_id.clone(),
        git_repo: request.git_repo.clone()?,
        git_branch: request.git_branch.clone()?,
        pack_hash: plan.pack_hash.clone()?,
    })
}

fn build_applied_context(
    plan: AgentContextPlan,
    runtime: RuntimeContextConfig,
) -> Option<AppliedAgentContext> {
    let max_context_tokens = usize::try_from(plan.max_context_tokens).ok()?;
    let filtered = plan
        .items
        .into_iter()
        .filter(|item| item.item_type.allowed(runtime))
        .collect::<Vec<_>>();

    if filtered.is_empty() {
        return None;
    }

    let mut selected = Vec::new();
    let mut selected_tokens = 0usize;
    for item in filtered {
        let item_tokens = usize::try_from(item.token_estimate).ok()?;
        if selected_tokens.saturating_add(item_tokens) > max_context_tokens {
            break;
        }
        selected_tokens = selected_tokens.saturating_add(item_tokens);
        selected.push(item);
    }

    if selected.is_empty() {
        return None;
    }

    let block = format_context_block(&selected);
    if block.trim().is_empty() {
        return None;
    }

    let mut telemetry = ContextSelectionTelemetry {
        plan_hash: plan.plan_hash,
        context_policy_version: plan.context_policy_version,
        pack_hash: plan.pack_hash.clone(),
        manifest_hash: plan.manifest_hash,
        ranking_policy_version: plan.ranking_policy_version,
        visibility_digest: plan.visibility_digest,
        citation_required_count: selected
            .iter()
            .filter(|item| item.citation_required)
            .count()
            .try_into()
            .ok()?,
        tokens: ContextTokenBreakdown {
            max_context_tokens: plan.max_context_tokens,
            estimated_tokens: u32::try_from(selected_tokens).ok()?,
            injected_tokens: u32::try_from(token_estimation::estimate_text_tokens(&block)).ok()?,
            ..ContextTokenBreakdown::default()
        },
        ..ContextSelectionTelemetry::default()
    };

    for item in selected {
        telemetry.selected_item_ids.push(item.item_id.clone());
        if let Some(lane) = item.hierarchy_lane.clone() {
            telemetry.selected_hierarchy_lanes.push(lane);
        }
        if let Some(receipt_id) = item.receipt_id.clone() {
            telemetry.selected_receipt_ids.push(receipt_id);
        }
        telemetry.selected_items.push(SelectedContextItemTelemetry {
            item_id: item.item_id.clone(),
            item_type: item.item_type.as_str().to_string(),
            source_history_session_id: item.source_history_session_id.clone(),
            hierarchy_lane: item.hierarchy_lane.clone(),
            receipt_id: item.receipt_id.clone(),
            receipt_confidence_score: item.receipt_confidence_score,
            receipt_verification_status: item.receipt_verification_status.clone(),
        });
        match item.item_type {
            ContextItemType::Other => {}
            ContextItemType::WorkingContext => {
                telemetry.tokens.working_context_tokens = telemetry
                    .tokens
                    .working_context_tokens
                    .saturating_add(item.token_estimate);
            }
        }
    }

    Some(AppliedAgentContext { block, telemetry })
}

fn format_context_block(items: &[AgentContextItem]) -> String {
    if items.is_empty() {
        return String::new();
    }

    let mut parts = vec![
        "Verdictan agent context: use the following selected context items only when relevant. \
         Respect their order and cite any item marked citation-required."
            .to_string(),
    ];
    for item in items {
        let source_id = item
            .source_history_session_id
            .as_deref()
            .unwrap_or(item.item_id.as_str());
        let citation_mode = if item.citation_required {
            "citation-required"
        } else {
            "citation-optional"
        };
        parts.push(format!(
            "[{}:{}:{}:{}] {}",
            item.item_type.as_str(),
            source_id,
            item.item_id,
            citation_mode,
            item.content
        ));
    }
    parts.join("\n\n")
}

fn normalize_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn build_local_context_plan(
    query: &str,
    recall: &context_recall::ContextRecallResult,
) -> Option<AgentContextPlan> {
    let items = recall
        .entries
        .iter()
        .filter_map(|entry| local_context_item_from_document(&entry.document))
        .collect::<Vec<_>>();
    if items.is_empty() {
        return None;
    }

    let total_tokens = items.iter().fold(0u32, |acc, item| {
        acc.saturating_add(item.token_estimate.max(1))
    });

    Some(AgentContextPlan {
        plan_hash: format!(
            "local:{}:{:016x}",
            recall.backend.as_str(),
            super::cache::l1::hash_context_query(query)
        ),
        context_policy_version: 0,
        max_context_tokens: total_tokens,
        _estimated_tokens: total_tokens,
        _working_context_tokens: total_tokens,
        items,
        pack_hash: None,
        manifest_hash: None,
        ranking_policy_version: None,
        visibility_digest: None,
    })
}

fn local_context_item_from_document(document: &Value) -> Option<AgentContextItem> {
    let item_id = value_string_field(document, "id")?;
    let content = value_string_field(document, "content")?;
    Some(AgentContextItem {
        item_id,
        item_type: ContextItemType::WorkingContext,
        _sentence_id: None,
        _sentence_index: None,
        _start_offset: None,
        _end_offset: None,
        source_history_session_id: optional_value_string_field(document, "history_session_id"),
        content,
        token_estimate: value_u32_field(document, "token_estimate"),
        citation_required: value_bool_field(document, "citation_required"),
        _rank_score: value_f64_field(document, "rank_score"),
        hierarchy_lane: None,
        receipt_id: None,
        receipt_confidence_score: None,
        receipt_verification_status: None,
    })
}

fn optional_value_string_field(document: &Value, key: &str) -> Option<String> {
    document
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn value_string_field(document: &Value, key: &str) -> Option<String> {
    optional_value_string_field(document, key)
}

fn value_u32_field(document: &Value, key: &str) -> u32 {
    document
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value.min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

fn value_bool_field(document: &Value, key: &str) -> bool {
    document.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn value_f64_field(document: &Value, key: &str) -> Option<f64> {
    document.get(key).and_then(Value::as_f64)
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

    // --- normalize_text ---

    #[test]
    fn normalize_text_none() {
        assert!(normalize_text(None).is_none());
    }

    #[test]
    fn normalize_text_empty() {
        assert!(normalize_text(Some("")).is_none());
    }

    #[test]
    fn normalize_text_whitespace_only() {
        assert!(normalize_text(Some("   ")).is_none());
    }

    #[test]
    fn normalize_text_trims() {
        assert_eq!(normalize_text(Some("  hello  ")), Some("hello".to_string()));
    }

    #[test]
    fn normalize_text_preserves_non_whitespace() {
        assert_eq!(normalize_text(Some("value")), Some("value".to_string()));
    }

    // --- is_false ---

    #[test]
    fn is_false_true_value() {
        assert!(!is_false(&true));
    }

    #[test]
    fn is_false_false_value() {
        assert!(is_false(&false));
    }

    // --- ContextItemType ---

    #[test]
    fn context_item_type_as_str() {
        assert_eq!(ContextItemType::WorkingContext.as_str(), "working_context");
        assert_eq!(ContextItemType::Other.as_str(), "other");
    }

    #[test]
    fn context_item_type_allowed_working_context_enabled() {
        let cfg = RuntimeContextConfig {
            allow_working_context: true,
        };
        assert!(ContextItemType::WorkingContext.allowed(cfg));
    }

    #[test]
    fn context_item_type_allowed_working_context_disabled() {
        let cfg = RuntimeContextConfig {
            allow_working_context: false,
        };
        assert!(!ContextItemType::WorkingContext.allowed(cfg));
    }

    #[test]
    fn context_item_type_other_always_disallowed() {
        let cfg = RuntimeContextConfig {
            allow_working_context: true,
        };
        assert!(!ContextItemType::Other.allowed(cfg));
    }

    // --- RuntimeContextConfig default ---

    #[test]
    fn runtime_context_config_default() {
        let cfg = RuntimeContextConfig::default();
        assert!(!cfg.allow_working_context);
    }

    // --- ContextTokenBreakdown default ---

    #[test]
    fn context_token_breakdown_default() {
        let b = ContextTokenBreakdown::default();
        assert_eq!(b.max_context_tokens, 0);
        assert_eq!(b.estimated_tokens, 0);
        assert_eq!(b.injected_tokens, 0);
        assert_eq!(b.working_context_tokens, 0);
    }

    #[test]
    fn context_token_breakdown_eq() {
        let a = ContextTokenBreakdown {
            max_context_tokens: 100,
            estimated_tokens: 50,
            injected_tokens: 30,
            working_context_tokens: 10,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // --- format_context_block ---

    #[test]
    fn format_context_block_empty() {
        assert_eq!(format_context_block(&[]), "");
    }

    #[test]
    fn format_context_block_single_item() {
        let items = vec![AgentContextItem {
            item_id: "item-1".to_string(),
            item_type: ContextItemType::WorkingContext,
            _sentence_id: None,
            _sentence_index: None,
            _start_offset: None,
            _end_offset: None,
            source_history_session_id: None,
            content: "Test content".to_string(),
            token_estimate: 10,
            citation_required: false,
            _rank_score: None,
            hierarchy_lane: None,
            receipt_id: None,
            receipt_confidence_score: None,
            receipt_verification_status: None,
        }];
        let block = format_context_block(&items);
        assert!(block.contains("Verdictan agent context"));
        assert!(block.contains("[working_context:item-1:item-1:citation-optional] Test content"));
    }

    #[test]
    fn format_context_block_with_citation_required() {
        let items = vec![AgentContextItem {
            item_id: "item-2".to_string(),
            item_type: ContextItemType::WorkingContext,
            _sentence_id: None,
            _sentence_index: None,
            _start_offset: None,
            _end_offset: None,
            source_history_session_id: Some("session-abc".to_string()),
            content: "Important fact".to_string(),
            token_estimate: 5,
            citation_required: true,
            _rank_score: None,
            hierarchy_lane: None,
            receipt_id: None,
            receipt_confidence_score: None,
            receipt_verification_status: None,
        }];
        let block = format_context_block(&items);
        assert!(block.contains("citation-required"));
        assert!(block.contains("session-abc"));
    }

    // --- AgentContextService::inject_into_chat_request ---

    #[test]
    fn inject_into_chat_request_adds_system_message() {
        let mut req = serde_json::json!({
            "messages": [{"role": "user", "content": "hi"}]
        });
        let ctx = AppliedAgentContext {
            block: "Context info".into(),
            telemetry: ContextSelectionTelemetry::default(),
        };
        let injected = AgentContextService::inject_into_chat_request(&mut req, &ctx);
        assert!(injected);
        let messages = req["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "Context info");
        assert_eq!(messages[0]["_verdictan_recalled"], true);
    }

    #[test]
    fn inject_into_chat_request_empty_block_noop() {
        let mut req = serde_json::json!({
            "messages": [{"role": "user", "content": "hi"}]
        });
        let ctx = AppliedAgentContext {
            block: "   ".into(),
            telemetry: ContextSelectionTelemetry::default(),
        };
        assert!(!AgentContextService::inject_into_chat_request(
            &mut req, &ctx
        ));
    }

    #[test]
    fn inject_into_chat_request_no_messages_key() {
        let mut req = serde_json::json!({"model": "gpt-4"});
        let ctx = AppliedAgentContext {
            block: "ctx".into(),
            telemetry: ContextSelectionTelemetry::default(),
        };
        assert!(!AgentContextService::inject_into_chat_request(
            &mut req, &ctx
        ));
    }

    // --- AgentContextService::inject_into_responses_request ---

    #[test]
    fn inject_into_responses_request_creates_input_when_absent() {
        let mut req = serde_json::json!({"model": "gpt-4"});
        let ctx = AppliedAgentContext {
            block: "context block".into(),
            telemetry: ContextSelectionTelemetry::default(),
        };
        let injected = AgentContextService::inject_into_responses_request(&mut req, &ctx);
        assert!(injected);
        let input = req["input"].as_array().unwrap();
        assert_eq!(input.len(), 1);
        assert_eq!(input[0]["role"], "system");
    }

    #[test]
    fn inject_into_responses_request_string_input() {
        let mut req = serde_json::json!({"input": "user question"});
        let ctx = AppliedAgentContext {
            block: "ctx".into(),
            telemetry: ContextSelectionTelemetry::default(),
        };
        let injected = AgentContextService::inject_into_responses_request(&mut req, &ctx);
        assert!(injected);
        let input = req["input"].as_array().unwrap();
        assert_eq!(input.len(), 2);
        assert_eq!(input[0]["role"], "system");
        assert_eq!(input[1], "user question");
    }

    #[test]
    fn inject_into_responses_request_array_input() {
        let mut req = serde_json::json!({
            "input": [{"role": "user", "content": "hi"}]
        });
        let ctx = AppliedAgentContext {
            block: "ctx".into(),
            telemetry: ContextSelectionTelemetry::default(),
        };
        let injected = AgentContextService::inject_into_responses_request(&mut req, &ctx);
        assert!(injected);
        let input = req["input"].as_array().unwrap();
        assert_eq!(input.len(), 2);
        assert_eq!(input[0]["role"], "system");
    }

    #[test]
    fn inject_into_responses_request_empty_block_noop() {
        let mut req = serde_json::json!({"input": []});
        let ctx = AppliedAgentContext {
            block: "  ".into(),
            telemetry: ContextSelectionTelemetry::default(),
        };
        assert!(!AgentContextService::inject_into_responses_request(
            &mut req, &ctx
        ));
    }

    // --- AgentContextService::join_url ---

    #[test]
    fn join_url_strips_duplicate_slashes() {
        let svc = AgentContextService::new(
            reqwest::Client::new(),
            None,
            "https://api.example.com/".into(),
            5000,
        );
        assert_eq!(
            svc.join_url("/v1/context"),
            "https://api.example.com/v1/context"
        );
    }

    #[test]
    fn join_url_no_trailing_slash() {
        let svc = AgentContextService::new(
            reqwest::Client::new(),
            None,
            "https://api.example.com".into(),
            5000,
        );
        assert_eq!(
            svc.join_url("v1/context"),
            "https://api.example.com/v1/context"
        );
    }

    // --- AgentContextService::timeout_ms ---

    #[test]
    fn timeout_ms_returns_configured_value() {
        let svc = AgentContextService::new(
            reqwest::Client::new(),
            None,
            "http://localhost".into(),
            3000,
        );
        assert_eq!(svc.timeout_ms(), 3000);
    }

    // --- build_applied_context ---

    #[test]
    fn build_applied_context_empty_items() {
        let plan = AgentContextPlan {
            plan_hash: "hash".into(),
            context_policy_version: 1,
            max_context_tokens: 1000,
            _estimated_tokens: 0,
            items: vec![],
            _working_context_tokens: 0,
            pack_hash: None,
            manifest_hash: None,
            ranking_policy_version: None,
            visibility_digest: None,
        };
        let runtime = RuntimeContextConfig {
            allow_working_context: true,
        };
        assert!(build_applied_context(plan, runtime).is_none());
    }

    #[test]
    fn build_applied_context_filters_disallowed_types() {
        let plan = AgentContextPlan {
            plan_hash: "hash".into(),
            context_policy_version: 1,
            max_context_tokens: 1000,
            _estimated_tokens: 50,
            items: vec![AgentContextItem {
                item_id: "item-1".into(),
                item_type: ContextItemType::Other,
                _sentence_id: None,
                _sentence_index: None,
                _start_offset: None,
                _end_offset: None,
                source_history_session_id: None,
                content: "Some content".into(),
                token_estimate: 10,
                citation_required: false,
                _rank_score: None,
                hierarchy_lane: None,
                receipt_id: None,
                receipt_confidence_score: None,
                receipt_verification_status: None,
            }],
            _working_context_tokens: 0,
            pack_hash: None,
            manifest_hash: None,
            ranking_policy_version: None,
            visibility_digest: None,
        };
        let runtime = RuntimeContextConfig {
            allow_working_context: true,
        };
        assert!(build_applied_context(plan, runtime).is_none());
    }

    #[test]
    fn build_applied_context_respects_token_budget() {
        let plan = AgentContextPlan {
            plan_hash: "hash".into(),
            context_policy_version: 1,
            max_context_tokens: 15,
            _estimated_tokens: 30,
            items: vec![
                AgentContextItem {
                    item_id: "item-1".into(),
                    item_type: ContextItemType::WorkingContext,
                    _sentence_id: None,
                    _sentence_index: None,
                    _start_offset: None,
                    _end_offset: None,
                    source_history_session_id: None,
                    content: "First".into(),
                    token_estimate: 10,
                    citation_required: false,
                    _rank_score: None,
                    hierarchy_lane: None,
                    receipt_id: None,
                    receipt_confidence_score: None,
                    receipt_verification_status: None,
                },
                AgentContextItem {
                    item_id: "item-2".into(),
                    item_type: ContextItemType::WorkingContext,
                    _sentence_id: None,
                    _sentence_index: None,
                    _start_offset: None,
                    _end_offset: None,
                    source_history_session_id: None,
                    content: "Second".into(),
                    token_estimate: 10,
                    citation_required: true,
                    _rank_score: None,
                    hierarchy_lane: None,
                    receipt_id: None,
                    receipt_confidence_score: None,
                    receipt_verification_status: None,
                },
            ],
            _working_context_tokens: 0,
            pack_hash: None,
            manifest_hash: None,
            ranking_policy_version: None,
            visibility_digest: None,
        };
        let runtime = RuntimeContextConfig {
            allow_working_context: true,
        };
        let applied = build_applied_context(plan, runtime).unwrap();
        assert_eq!(applied.telemetry.selected_item_ids.len(), 1);
        assert_eq!(applied.telemetry.selected_item_ids[0], "item-1");
    }

    #[test]
    fn build_applied_context_tracks_citation_count() {
        let plan = AgentContextPlan {
            plan_hash: "hash".into(),
            context_policy_version: 2,
            max_context_tokens: 1000,
            _estimated_tokens: 20,
            items: vec![
                AgentContextItem {
                    item_id: "c1".into(),
                    item_type: ContextItemType::WorkingContext,
                    _sentence_id: None,
                    _sentence_index: None,
                    _start_offset: None,
                    _end_offset: None,
                    source_history_session_id: None,
                    content: "Cited".into(),
                    token_estimate: 5,
                    citation_required: true,
                    _rank_score: None,
                    hierarchy_lane: None,
                    receipt_id: None,
                    receipt_confidence_score: None,
                    receipt_verification_status: None,
                },
                AgentContextItem {
                    item_id: "c2".into(),
                    item_type: ContextItemType::WorkingContext,
                    _sentence_id: None,
                    _sentence_index: None,
                    _start_offset: None,
                    _end_offset: None,
                    source_history_session_id: None,
                    content: "Not cited".into(),
                    token_estimate: 5,
                    citation_required: false,
                    _rank_score: None,
                    hierarchy_lane: None,
                    receipt_id: None,
                    receipt_confidence_score: None,
                    receipt_verification_status: None,
                },
            ],
            _working_context_tokens: 0,
            pack_hash: Some("pack-xyz".into()),
            manifest_hash: Some("manifest-abc".into()),
            ranking_policy_version: Some("v3".into()),
            visibility_digest: Some("digest-xyz".into()),
        };
        let runtime = RuntimeContextConfig {
            allow_working_context: true,
        };
        let applied = build_applied_context(plan, runtime).unwrap();
        assert_eq!(applied.telemetry.citation_required_count, 1);
        assert_eq!(applied.telemetry.pack_hash.as_deref(), Some("pack-xyz"));
        assert_eq!(
            applied.telemetry.manifest_hash.as_deref(),
            Some("manifest-abc")
        );
        assert_eq!(
            applied.telemetry.ranking_policy_version.as_deref(),
            Some("v3")
        );
        assert_eq!(
            applied.telemetry.visibility_digest.as_deref(),
            Some("digest-xyz")
        );
    }
}
