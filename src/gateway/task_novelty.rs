// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::BTreeSet;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::session::GatewaySessionContext;

const DEFAULT_SEARCH_LIMIT: u32 = 5;

#[derive(Clone)]
pub struct TaskNoveltyService {
    client: reqwest::Client,
    gateway_client: Option<reqwest::Client>,
    api_base: String,
    timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoveltyClass {
    ExactRepeat,
    NearRepeat,
    KnownPatternNewLocation,
    #[default]
    Novel,
}

impl NoveltyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactRepeat => "exact_repeat",
            Self::NearRepeat => "near_repeat",
            Self::KnownPatternNewLocation => "known_pattern_new_location",
            Self::Novel => "novel",
        }
    }

    fn from_api_value(value: Option<&str>) -> Self {
        match value.unwrap_or_default() {
            "exact_repeat" => Self::ExactRepeat,
            "near_repeat" => Self::NearRepeat,
            "known_pattern_new_location" => Self::KnownPatternNewLocation,
            _ => Self::Novel,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TaskNoveltyHints {
    pub error_signature_hashes: Vec<String>,
    pub file_paths: Vec<String>,
    pub symbols: Vec<String>,
    pub package_scope: Option<String>,
    pub command_names: Vec<String>,
    pub working_directory: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskFingerprint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_prompt_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_fingerprint_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_signature_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_scope_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol_scope_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_scope: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TaskNoveltyRequest {
    pub team_id: Option<String>,
    pub agent_id: Option<String>,
    pub git_repo: String,
    pub git_branch: Option<String>,
    pub normalized_prompt_hash: Option<String>,
    pub task_fingerprint_hash: Option<String>,
    pub error_signature_hashes: Vec<String>,
    pub file_paths: Vec<String>,
    pub symbols: Vec<String>,
    pub package_scope: Option<String>,
    pub command_names: Vec<String>,
    pub working_directory: Option<String>,
    pub fingerprint: TaskFingerprint,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TaskNoveltyAssessment {
    pub novelty_class: NoveltyClass,
    pub matched_receipt: Option<WorkReceiptMatch>,
    pub candidate_receipts: Vec<WorkReceiptMatch>,
    pub request: TaskNoveltyRequest,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkReceiptFile {
    pub file_path: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkReceiptSymbol {
    pub symbol_name: String,
    #[serde(default)]
    pub symbol_kind: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkReceiptCommand {
    pub command_text: String,
    #[serde(default)]
    pub output_preview: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkReceiptError {
    pub error_signature_hash: String,
    pub error_message: String,
    #[serde(default)]
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WorkReceiptMatch {
    pub receipt_id: String,
    #[serde(default)]
    pub intent: String,
    #[serde(default)]
    pub patch_summary: Option<String>,
    #[serde(default)]
    pub final_outcome: String,
    #[serde(default)]
    pub verification_status: String,
    #[serde(default)]
    pub confidence_score: f64,
    #[serde(default)]
    pub files: Vec<WorkReceiptFile>,
    #[serde(default)]
    pub symbols: Vec<WorkReceiptSymbol>,
    #[serde(default)]
    pub commands: Vec<WorkReceiptCommand>,
    #[serde(default)]
    pub errors: Vec<WorkReceiptError>,
    #[serde(default)]
    pub match_novelty_class: Option<String>,
    #[serde(default)]
    pub exact_hash_match: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
struct SearchWorkReceiptsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    git_repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    normalized_prompt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task_fingerprint_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    error_signature_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    file_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    symbols: Vec<String>,
    limit: u32,
}

#[derive(Clone, Debug, Serialize)]
struct GatewaySearchWorkReceiptsRequest {
    org_id: String,
    #[serde(flatten)]
    inner: SearchWorkReceiptsRequest,
}

#[derive(Clone, Debug, Deserialize)]
struct SearchWorkReceiptsResponse {
    receipts: Vec<WorkReceiptMatch>,
}

impl TaskNoveltyService {
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

    pub async fn classify_task_novelty(
        &self,
        session: &GatewaySessionContext,
        request: &TaskNoveltyRequest,
    ) -> anyhow::Result<TaskNoveltyAssessment> {
        let gateway_payload = SearchWorkReceiptsRequest {
            team_id: request.team_id.clone(),
            agent_id: request.agent_id.clone(),
            git_repo: request.git_repo.clone(),
            git_branch: request.git_branch.clone(),
            normalized_prompt_hash: request.normalized_prompt_hash.clone(),
            task_fingerprint_hash: request.task_fingerprint_hash.clone(),
            error_signature_hashes: request.error_signature_hashes.clone(),
            file_paths: request.file_paths.clone(),
            symbols: request.symbols.clone(),
            limit: DEFAULT_SEARCH_LIMIT,
        };
        let org_id = normalize_scalar(session._org_id.as_deref());
        let (client, url, body) = match (&self.gateway_client, org_id.as_deref()) {
            (Some(client), Some(org_id)) => (
                client,
                self.join_url("/v1/gateway/work-receipts/search"),
                serde_json::to_value(GatewaySearchWorkReceiptsRequest {
                    org_id: org_id.to_string(),
                    inner: gateway_payload,
                })?,
            ),
            (Some(_), None) => anyhow::bail!("gateway work receipt search missing org_id"),
            (None, _) => (
                &self.client,
                self.join_url("/v1/work-receipts/search"),
                serde_json::to_value(gateway_payload)?,
            ),
        };

        let response = client
            .post(url)
            .json(&body)
            .send()
            .await
            .context("task novelty search failed")?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "{}",
                super::machine_route_error::classify_and_format(
                    "work-receipts/search",
                    status,
                    &text,
                )
            );
        }
        let payload = response
            .json::<SearchWorkReceiptsResponse>()
            .await
            .context("failed to decode work receipt search response")?;
        let matched_receipt = payload.receipts.first().cloned();
        let novelty_class = matched_receipt
            .as_ref()
            .map(|receipt| NoveltyClass::from_api_value(receipt.match_novelty_class.as_deref()))
            .unwrap_or(NoveltyClass::Novel);

        Ok(TaskNoveltyAssessment {
            novelty_class,
            matched_receipt,
            candidate_receipts: payload.receipts,
            request: request.clone(),
        })
    }

    fn join_url(&self, path: &str) -> String {
        let base = self.api_base.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{base}/{path}")
    }
}

pub fn build_task_novelty_request(
    session: &GatewaySessionContext,
    request_text: Option<&str>,
    request_json: &Value,
) -> Option<TaskNoveltyRequest> {
    let git_repo = normalize_scalar(
        session
            .git_context
            .as_ref()
            .and_then(|context| context.repo.as_deref()),
    )?;
    let git_branch = normalize_scalar(
        session
            .git_context
            .as_ref()
            .and_then(|context| context.branch.as_deref()),
    );
    let hints = extract_task_novelty_hints(request_json);
    let fingerprint = compute_task_fingerprint(request_text, &hints);

    Some(TaskNoveltyRequest {
        team_id: normalize_scalar(session.team_id.as_deref()),
        agent_id: normalize_scalar(session.agent_id.as_deref()),
        git_repo,
        git_branch,
        normalized_prompt_hash: fingerprint.normalized_prompt_hash.clone(),
        task_fingerprint_hash: fingerprint.task_fingerprint_hash.clone(),
        error_signature_hashes: hints.error_signature_hashes.clone(),
        file_paths: hints.file_paths.clone(),
        symbols: hints.symbols.clone(),
        package_scope: fingerprint.package_scope.clone(),
        command_names: hints.command_names,
        working_directory: hints.working_directory,
        fingerprint,
    })
}

pub fn extract_task_novelty_hints(request_json: &Value) -> TaskNoveltyHints {
    let fabric = request_json
        .pointer("/verdictan/context_fabric")
        .or_else(|| request_json.get("context_fabric"));
    let Some(fabric) = fabric else {
        return TaskNoveltyHints::default();
    };
    TaskNoveltyHints {
        error_signature_hashes: value_string_array(fabric.get("error_signature_hashes")),
        file_paths: value_string_array(fabric.get("file_paths")),
        symbols: value_string_array(fabric.get("symbols")),
        package_scope: fabric
            .get("package_scope")
            .and_then(Value::as_str)
            .and_then(|value| normalize_scalar(Some(value))),
        command_names: value_string_array(fabric.get("command_names")),
        working_directory: fabric
            .get("working_directory")
            .and_then(Value::as_str)
            .and_then(|value| normalize_scalar(Some(value))),
    }
}

fn value_string_array(value: Option<&Value>) -> Vec<String> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    normalize_scalar_unique(
        items
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|value| normalize_scalar(Some(value))),
    )
}

fn compute_task_fingerprint(
    request_text: Option<&str>,
    hints: &TaskNoveltyHints,
) -> TaskFingerprint {
    let normalized_prompt_hash = hash_optional_text("prompt", request_text);
    let error_signatures = normalize_fingerprint_unique(
        hints
            .error_signature_hashes
            .iter()
            .filter_map(|value| normalize_fingerprint_text(Some(value.as_str()))),
    );
    let file_paths = normalize_fingerprint_unique(hints.file_paths.iter().filter_map(|value| {
        normalize_path_for_fingerprint(value)
            .and_then(|path| normalize_fingerprint_text(Some(path.as_str())))
    }));
    let symbols = normalize_fingerprint_unique(
        hints
            .symbols
            .iter()
            .filter_map(|value| normalize_fingerprint_text(Some(value.as_str()))),
    );
    let command_names =
        normalize_fingerprint_unique(hints.command_names.iter().filter_map(|value| {
            value
                .split_whitespace()
                .next()
                .and_then(|token| normalize_fingerprint_text(Some(token)))
        }));
    let package_scope = normalize_package_scope(hints.package_scope.as_deref(), &file_paths);

    let error_signature_hash = hash_joined("error", &error_signatures);
    let file_scope_hash = hash_joined("file", &file_paths);
    let symbol_scope_hash = hash_joined("symbol", &symbols);
    let command_scope_hash = hash_joined("command", &command_names);
    let task_fingerprint_hash = {
        let parts = [
            normalized_prompt_hash
                .as_ref()
                .map(|value| format!("prompt={value}")),
            error_signature_hash
                .as_ref()
                .map(|value| format!("error={value}")),
            file_scope_hash
                .as_ref()
                .map(|value| format!("file={value}")),
            symbol_scope_hash
                .as_ref()
                .map(|value| format!("symbol={value}")),
            package_scope
                .as_ref()
                .map(|value| format!("package={value}")),
            command_scope_hash
                .as_ref()
                .map(|value| format!("command={value}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        (!parts.is_empty()).then(|| sha256_hex(parts.join("\n").as_bytes()))
    };

    TaskFingerprint {
        normalized_prompt_hash,
        task_fingerprint_hash,
        error_signature_hash,
        file_scope_hash,
        symbol_scope_hash,
        package_scope,
    }
}

fn normalize_package_scope(explicit: Option<&str>, file_paths: &[String]) -> Option<String> {
    normalize_fingerprint_text(explicit).or_else(|| {
        let derived = file_paths
            .iter()
            .map(|path| derive_package_scope(path))
            .collect::<BTreeSet<_>>();
        (!derived.is_empty()).then(|| derived.into_iter().collect::<Vec<_>>().join("|"))
    })
}

fn derive_package_scope(path: &str) -> String {
    let segments = path
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if segments.len() >= 4 && segments[1] == "src" && segments[2] == "domains" {
        return segments[..4].join("/");
    }
    if segments.len() >= 3 && segments[1] == "src" {
        return segments[..3].join("/");
    }
    if segments.len() >= 2 {
        return segments[..2].join("/");
    }
    segments.first().copied().unwrap_or_default().to_string()
}

fn normalize_path_for_fingerprint(value: &str) -> Option<String> {
    let normalized = value
        .trim()
        .replace('\\', "/")
        .trim_start_matches("./")
        .trim_matches('/')
        .to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

fn normalize_scalar_unique<I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut deduped = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        deduped.insert(trimmed.to_string());
    }
    deduped.into_iter().collect()
}

fn normalize_fingerprint_unique<I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    normalize_scalar_unique(values)
}

fn normalize_scalar(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_fingerprint_text(value: Option<&str>) -> Option<String> {
    value
        .map(|candidate| candidate.split_whitespace().collect::<Vec<_>>().join(" "))
        .map(|candidate| candidate.trim().to_ascii_lowercase())
        .filter(|candidate| !candidate.is_empty())
}

fn hash_optional_text(prefix: &str, value: Option<&str>) -> Option<String> {
    normalize_fingerprint_text(value).map(|text| sha256_hex(format!("{prefix}:{text}").as_bytes()))
}

fn hash_joined(prefix: &str, values: &[String]) -> Option<String> {
    (!values.is_empty()).then(|| sha256_hex(format!("{prefix}:{}", values.join("\n")).as_bytes()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;

    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
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

    const TEST_WORKING_DIRECTORY: &str = env!("CARGO_MANIFEST_DIR");

    fn session() -> GatewaySessionContext {
        GatewaySessionContext {
            _org_id: Some("org-1".to_string()),
            team_id: Some("team-1".to_string()),
            agent_id: Some("agent-1".to_string()),
            git_context: Some(super::super::session::GatewayGitContext {
                repo: Some("verdictan/verdictan".to_string()),
                branch: Some("feature/reuse".to_string()),
                commit: None,
            }),
            ..GatewaySessionContext::default()
        }
    }

    #[test]
    fn build_task_novelty_request_extracts_context_fabric_hints() {
        let request = serde_json::json!({
            "verdictan": {
                "context_fabric": {
                    "error_signature_hashes": ["ERR_SQLX"],
                    "file_paths": ["api/src/domains/gateway/work_receipts.rs"],
                    "symbols": ["create_work_receipt_with_repo"],
                    "package_scope": "api/src/domains/gateway",
                    "command_names": ["cargo nextest run --test work_receipts"],
                    "working_directory": TEST_WORKING_DIRECTORY
                }
            }
        });

        let novelty =
            build_task_novelty_request(&session(), Some("Fix sqlx receipt test"), &request)
                .expect("novelty request");

        assert_eq!(novelty.git_repo, "verdictan/verdictan");
        assert_eq!(novelty.error_signature_hashes, vec!["ERR_SQLX".to_string()]);
        assert_eq!(
            novelty.file_paths,
            vec!["api/src/domains/gateway/work_receipts.rs".to_string()]
        );
        assert_eq!(
            novelty.package_scope.as_deref(),
            Some("api/src/domains/gateway")
        );
        assert_eq!(
            novelty.working_directory.as_deref(),
            Some(TEST_WORKING_DIRECTORY)
        );
        assert!(novelty.normalized_prompt_hash.is_some());
        assert!(novelty.task_fingerprint_hash.is_some());
    }

    #[test]
    fn novelty_class_from_api_defaults_to_novel() {
        assert_eq!(NoveltyClass::from_api_value(None), NoveltyClass::Novel);
        assert_eq!(
            NoveltyClass::from_api_value(Some("known_pattern_new_location")),
            NoveltyClass::KnownPatternNewLocation
        );
    }
}
