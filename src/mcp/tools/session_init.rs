// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP tool: session_init

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use chrono::Utc;
use serde_json::{Map, Value};

use super::ToolContext;
use crate::error::CliError;
use crate::gateway::{
    graph_populator::{self, GraphUpsertPayload, SourceFileGraphInput},
    ground_truth::{
        self, ContentAddressableRef, GitShowSourceMaterialResolver, SourceMaterialResolver,
    },
};
use crate::mcp::local_context_runtime::{
    shared_local_context_runtime_registry, LocalContextSessionScope,
};

const MAX_GRAPH_SOURCE_FILES: usize = 20;
const VERIFICATION_PREVIEW_LIMIT: u64 = 20;

pub(crate) fn definition() -> Value {
    serde_json::json!({
        "name": "session_init",
        "description": "Register repository and branch context for the current MCP session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {
                    "type": "string",
                    "description": "Repository identifier or remote URL for the current coding session."
                },
                "branch": {
                    "type": "string",
                    "description": "Current git branch name."
                },
                "commit": {
                    "type": "string",
                    "description": "Optional current commit SHA."
                },
                "working_directory": {
                    "type": "string",
                    "description": "Optional working directory path for the session."
                },
                "team_id": {
                    "type": "string",
                    "description": "Optional explicit team scope override."
                }
            },
            "required": ["repo", "branch"]
        }
    })
}

pub(crate) async fn execute(ctx: &ToolContext<'_>, arguments: &Value) -> Result<Value, CliError> {
    let repo = required_string_argument(arguments, "repo")?;
    let branch = required_string_argument(arguments, "branch")?;
    let commit = optional_string_argument(arguments, "commit")?;
    let working_directory = optional_string_argument(arguments, "working_directory")?;
    let team_id = optional_string_argument(arguments, "team_id")?;

    let mut body = Map::new();
    body.insert(
        "session_id".to_string(),
        Value::String(ctx.session_id.to_string()),
    );
    body.insert("repo".to_string(), Value::String(repo.clone()));
    body.insert("branch".to_string(), Value::String(branch.clone()));
    if let Some(value) = team_id.clone() {
        body.insert("team_id".to_string(), Value::String(value));
    }
    if let Some(value) = commit.clone() {
        body.insert("commit".to_string(), Value::String(value));
    }
    if let Some(value) = working_directory.clone() {
        body.insert("working_directory".to_string(), Value::String(value));
    }

    tracing::debug!(
        session_id = %ctx.session_id,
        repo = %repo,
        branch = %branch,
        "registering MCP context-fabric session"
    );

    let response = ctx
        .client
        .post_json_value("/v1/context/register", &Value::Object(body))
        .await?;
    shared_local_context_runtime_registry()
        .session(ctx.session_id.to_string())
        .set_scope(Some(LocalContextSessionScope {
            team_id: optional_output_string(&response, "team_id"),
            repo: optional_output_string(&response, "repo"),
            branch: optional_output_string(&response, "branch"),
            commit: optional_output_string(&response, "commit"),
            working_directory: optional_output_string(&response, "working_directory"),
        }));

    let mut output = Map::new();
    output.insert(
        "tool_name".to_string(),
        Value::String("session_init".to_string()),
    );
    output.insert("status".to_string(), Value::String("ok".to_string()));
    output.insert(
        "scope".to_string(),
        serde_json::json!({
            "kind": "branch",
            "session_id": ctx.session_id,
            "team_id": optional_output_string(&response, "team_id"),
            "repo": string_field(&response, "repo"),
            "branch": string_field(&response, "branch"),
            "resolved_scope_known": true,
            "resolution": "registered_session",
        }),
    );
    output.insert(
        "registration".to_string(),
        normalize_registration(&response),
    );
    output.insert(
        "ground_truth_scope".to_string(),
        ground_truth::session_scope_metadata(&response),
    );
    let advanced_infra = follow_through_advanced_infra(ctx, &response).await;
    output.insert(
        "graph_follow_through".to_string(),
        advanced_infra
            .get("graph_population")
            .cloned()
            .unwrap_or(Value::Null),
    );
    output.insert("advanced_infra".to_string(), advanced_infra);
    if let Some(summary) = response.get("branch_context_summary") {
        output.insert("branch_context_summary".to_string(), summary.clone());
    }

    Ok(Value::Object(output))
}

async fn follow_through_advanced_infra(ctx: &ToolContext<'_>, registration: &Value) -> Value {
    let requested = optional_output_string(registration, "commit").is_some()
        && optional_output_string(registration, "working_directory").is_some();
    let graph = follow_through_context_graph_registration(ctx, registration).await;
    let verification = if graph.verification_ready {
        apply_context_verification(
            ctx,
            graph.repo.as_deref(),
            graph.branch.as_deref(),
            graph.team_id.as_deref(),
            graph.repo_root.as_deref(),
        )
        .await
    } else if requested {
        skipped_verification_preview(
            "verification_prerequisites_unmet",
            "Verification preview skipped because the working directory or git material was unavailable for bounded session_init follow-through.",
        )
    } else {
        skipped_verification_preview(
            "missing_context",
            "Verification preview skipped because both commit and working_directory are required.",
        )
    };

    let mut notes = Vec::new();
    if let Some(note) = optional_output_string(&graph.value, "note") {
        push_note(&mut notes, note);
    }
    if let Some(note) = optional_output_string(&verification, "note") {
        push_note(&mut notes, note);
    }

    serde_json::json!({
        "requested": requested,
        "status": if requested { "best_effort" } else { "skipped" },
        "graph_population": graph.value,
        "verification": verification,
        "notes": notes,
    })
}

async fn follow_through_context_graph_registration(
    ctx: &ToolContext<'_>,
    registration: &Value,
) -> GraphFollowThroughOutcome {
    let Some(repo) = optional_output_string(registration, "repo") else {
        return GraphFollowThroughOutcome::skipped(serde_json::json!({
            "status": "skipped",
            "reason": "missing_registered_repo",
            "note": "Advanced-infra graph population skipped because the registration response did not include a repo.",
        }));
    };
    let Some(branch) = optional_output_string(registration, "branch") else {
        return GraphFollowThroughOutcome::skipped(serde_json::json!({
            "status": "skipped",
            "reason": "missing_registered_branch",
            "note": "Advanced-infra graph population skipped because the registration response did not include a branch.",
        }));
    };

    let commit = optional_output_string(registration, "commit");
    let working_directory = optional_output_string(registration, "working_directory");
    let team_id = optional_output_string(registration, "team_id");

    let mut missing_fields = Vec::new();
    if commit.is_none() {
        missing_fields.push("commit");
    }
    if working_directory.is_none() {
        missing_fields.push("working_directory");
    }
    if !missing_fields.is_empty() {
        return GraphFollowThroughOutcome::skipped(serde_json::json!({
            "status": "skipped",
            "reason": "missing_context",
            "missing_fields": missing_fields,
            "note": "Advanced-infra graph population skipped because both commit and working_directory are required.",
        }));
    }

    let commit = commit.unwrap_or_default();
    let working_directory = working_directory.unwrap_or_default();
    let repo_root = match resolve_repo_root(Path::new(&working_directory)) {
        Ok(value) => value,
        Err(message) => {
            return GraphFollowThroughOutcome::skipped(serde_json::json!({
                "status": "skipped",
                "reason": "working_directory_unavailable",
                "working_directory": working_directory,
                "message": message,
                "note": "Advanced-infra graph population skipped because the provided working_directory was not accessible.",
            }));
        }
    };

    let changed_files = match list_changed_commit_files(&repo_root, &commit) {
        Ok(value) => value,
        Err(message) => {
            return GraphFollowThroughOutcome::skipped(serde_json::json!({
                "status": "skipped",
                "reason": "commit_unavailable",
                "commit": commit,
                "repo_root": repo_root.display().to_string(),
                "message": message,
                "note": "Advanced-infra graph population skipped because git material for the requested commit was unavailable.",
            }));
        }
    };

    let supported_files = changed_files
        .iter()
        .filter(|path| is_graph_supported_source_file(path))
        .cloned()
        .collect::<Vec<_>>();
    if supported_files.is_empty() {
        return GraphFollowThroughOutcome::verification_ready(
            serde_json::json!({
                "status": "skipped",
                "reason": "no_supported_commit_files",
                "commit": commit,
                "repo_root": repo_root.display().to_string(),
                "changed_file_count": changed_files.len(),
                "supported_file_count": 0,
                "note": "Advanced-infra graph population skipped because the requested commit did not expose any supported changed source files.",
            }),
            repo,
            branch,
            team_id,
            repo_root,
        );
    }

    let selected_files = supported_files
        .iter()
        .take(MAX_GRAPH_SOURCE_FILES)
        .cloned()
        .collect::<Vec<_>>();
    let truncated = supported_files.len() > selected_files.len();
    let resolver = GitShowSourceMaterialResolver::new(repo_root.clone());
    let captured_at = Utc::now();
    let mut aggregate_nodes = Vec::new();
    let mut aggregate_edges = Vec::new();
    let mut warnings = Vec::new();
    let mut processed_paths = Vec::new();
    let mut skipped_paths = Vec::new();

    for path in &selected_files {
        let Some(reference) = ContentAddressableRef::from_parts(&commit, path) else {
            skipped_paths.push(serde_json::json!({
                "path": path,
                "reason": "invalid_content_addressable_ref",
            }));
            continue;
        };
        let source_bytes = match resolver.resolve(&reference) {
            Ok(value) => value,
            Err(message) => {
                skipped_paths.push(serde_json::json!({
                    "path": path,
                    "reason": "git_show_failed",
                }));
                warnings.push(message);
                continue;
            }
        };
        let contents = match String::from_utf8(source_bytes) {
            Ok(value) => value,
            Err(_) => {
                skipped_paths.push(serde_json::json!({
                    "path": path,
                    "reason": "non_utf8_source",
                }));
                continue;
            }
        };
        let payload = graph_populator::prepare_source_file_upsert_payload(&SourceFileGraphInput {
            repo: Some(repo.clone()),
            branch: Some(branch.clone()),
            commit: Some(commit.clone()),
            path: path.clone(),
            contents,
            captured_at,
        });
        aggregate_nodes.extend(payload.nodes);
        aggregate_edges.extend(payload.edges);
        warnings.extend(payload.warnings);
        processed_paths.push(path.clone());
    }

    if aggregate_nodes.is_empty() && aggregate_edges.is_empty() {
        return GraphFollowThroughOutcome::verification_ready(
            serde_json::json!({
                "status": "skipped",
                "reason": "no_graph_entities_extracted",
                "commit": commit,
                "repo_root": repo_root.display().to_string(),
                "changed_file_count": changed_files.len(),
                "supported_file_count": supported_files.len(),
                "selected_file_count": selected_files.len(),
                "processed_file_count": processed_paths.len(),
                "processed_paths": processed_paths,
                "skipped_paths": skipped_paths,
                "warnings": warnings,
                "truncated": truncated,
                "note": "Advanced-infra graph population extracted no graph payload from the accessible changed source files.",
            }),
            repo,
            branch,
            team_id,
            repo_root,
        );
    }

    let mut body = match serde_json::to_value(GraphUpsertPayload {
        repo: Some(repo.clone()),
        branch: Some(branch.clone()),
        nodes: aggregate_nodes,
        edges: aggregate_edges,
        warnings: warnings.clone(),
    }) {
        Ok(value) => value,
        Err(error) => {
            return GraphFollowThroughOutcome::verification_ready(
                serde_json::json!({
                    "status": "error",
                    "reason": "graph_payload_serialization_failed",
                    "message": error.to_string(),
                    "note": "Advanced-infra graph payload extraction succeeded, but the graph payload could not be serialized.",
                }),
                repo,
                branch,
                team_id,
                repo_root,
            );
        }
    };
    let Some(body_object) = body.as_object_mut() else {
        return GraphFollowThroughOutcome::verification_ready(
            serde_json::json!({
                "status": "error",
                "reason": "graph_payload_not_object",
                "note": "Advanced-infra graph payload extraction succeeded, but the graph payload was not serializable as an object.",
            }),
            repo,
            branch,
            team_id,
            repo_root,
        );
    };
    if let Some(team_id) = team_id.as_ref() {
        body_object.insert("team_id".to_string(), Value::String(team_id.clone()));
    }

    let value = match ctx
        .client
        .post_json_value("/v1/context/graph/upsert", &body)
        .await
    {
        Ok(response) => serde_json::json!({
            "status": "applied",
            "reason": "graph_upserted",
            "commit": commit,
            "repo_root": repo_root.display().to_string(),
            "changed_file_count": changed_files.len(),
            "supported_file_count": supported_files.len(),
            "selected_file_count": selected_files.len(),
            "processed_file_count": processed_paths.len(),
            "processed_paths": processed_paths,
            "skipped_paths": skipped_paths,
            "warnings": warnings,
            "truncated": truncated,
            "graph_upsert": {
                "node_count": array_len(&response, "nodes"),
                "edge_count": array_len(&response, "edges"),
                "conflict_count": array_len(&response, "conflicts"),
            },
            "note": Value::Null,
        }),
        Err(error) => {
            let (status, reason) = match error.http_status() {
                Some(404) => ("unavailable", "context_graph_endpoint_unavailable"),
                Some(401 | 403) => ("blocked", "context_graph_upsert_forbidden"),
                Some(422) => ("blocked", "context_graph_upsert_rejected"),
                _ => ("error", "context_graph_upsert_failed"),
            };
            serde_json::json!({
                "status": status,
                "reason": reason,
                "commit": commit,
                "repo_root": repo_root.display().to_string(),
                "changed_file_count": changed_files.len(),
                "supported_file_count": supported_files.len(),
                "selected_file_count": selected_files.len(),
                "processed_file_count": processed_paths.len(),
                "processed_paths": processed_paths,
                "skipped_paths": skipped_paths,
                "warnings": warnings,
                "truncated": truncated,
                "error": {
                    "http_status": error.http_status(),
                    "message": error.to_string(),
                },
                "note": "Advanced-infra graph payload extraction succeeded, but POST /v1/context/graph/upsert did not complete successfully.",
            })
        }
    };

    GraphFollowThroughOutcome::verification_ready(value, repo, branch, team_id, repo_root)
}

async fn apply_context_verification(
    ctx: &ToolContext<'_>,
    repo: Option<&str>,
    branch: Option<&str>,
    team_id: Option<&str>,
    repo_root: Option<&Path>,
) -> Value {
    let (Some(repo), Some(branch), Some(repo_root)) = (repo, branch, repo_root) else {
        return skipped_verification_preview(
            "verification_prerequisites_unmet",
            "Verification apply skipped because the repo, branch, or working directory could not be resolved.",
        );
    };

    let path = build_recent_preview_path(
        Some(ctx.session_id),
        team_id,
        Some(repo),
        Some(branch),
        Some(VERIFICATION_PREVIEW_LIMIT),
    );
    let response = match ctx.client.get_json_value(&path).await {
        Ok(response) => response,
        Err(error) => {
            return skipped_verification_preview(
                "recent_context_unavailable",
                &format!(
                    "Verification apply skipped because the current API seams could not load bounded recent context targets: {error}"
                ),
            );
        }
    };

    let documents = response
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if documents.is_empty() {
        return skipped_verification_preview(
            "no_recent_context_documents",
            "Verification apply skipped because no recent context documents were available for the current repo and branch.",
        );
    }

    let targets = documents
        .iter()
        .map(ground_truth::verification_target_from_document)
        .collect::<Vec<_>>();
    let report = ground_truth::verify_targets_in_repo(repo_root, &targets, Utc::now());
    let applicable_outcomes = build_verification_apply_outcomes(&report.outcomes);
    if applicable_outcomes.is_empty() {
        let note = if report
            .outcomes
            .iter()
            .all(|outcome| outcome.decision == ground_truth::VerificationDecision::Skipped)
        {
            "Verification apply skipped because the bounded recent context targets did not expose any verifiable commit-bound material."
        } else {
            "Verification apply skipped because no bounded verification outcomes were eligible to persist."
        };

        return serde_json::json!({
            "status": "skipped",
            "reason": "no_applicable_verification_outcomes",
            "persisted": false,
            "target_count": targets.len(),
            "applicable_outcome_count": 0,
            "reverified": report.reverified,
            "stale": report.stale,
            "skipped": report.skipped,
            "outcomes": report.outcomes,
            "note": note,
        });
    }

    let mut body = Map::new();
    body.insert(
        "session_id".to_string(),
        Value::String(ctx.session_id.to_string()),
    );
    body.insert("repo".to_string(), Value::String(repo.to_string()));
    body.insert("branch".to_string(), Value::String(branch.to_string()));
    if let Some(team_id) = team_id.filter(|value| !value.trim().is_empty()) {
        body.insert("team_id".to_string(), Value::String(team_id.to_string()));
    }
    body.insert(
        "outcomes".to_string(),
        Value::Array(applicable_outcomes.clone()),
    );

    match ctx
        .client
        .post_json_value("/v1/context/verification/apply", &Value::Object(body))
        .await
    {
        Ok(response) => {
            let updated = response.get("updated").and_then(Value::as_i64).unwrap_or(0);
            let skipped_updates = response.get("skipped").and_then(Value::as_i64).unwrap_or(0);

            serde_json::json!({
                "status": if updated > 0 { "applied" } else { "skipped" },
                "reason": if updated > 0 {
                    "verification_outcomes_persisted"
                } else {
                    "verification_outcomes_not_updated"
                },
                "persisted": updated > 0,
                "target_count": targets.len(),
                "applicable_outcome_count": applicable_outcomes.len(),
                "reverified": report.reverified,
                "stale": report.stale,
                "skipped": report.skipped,
                "outcomes": report.outcomes,
                "apply_response": {
                    "updated": updated,
                    "skipped": skipped_updates,
                    "outcomes": response
                        .get("outcomes")
                        .cloned()
                        .unwrap_or_else(|| Value::Array(Vec::new())),
                },
                "note": if report.skipped > 0 {
                    Value::String("Verification outcomes were persisted for the applicable reverified or stale targets; unverifiable targets were left unchanged.".to_string())
                } else {
                    Value::Null
                },
            })
        }
        Err(error) => {
            let (status, reason) = match error.http_status() {
                Some(404) => ("unavailable", "verification_apply_endpoint_unavailable"),
                Some(401 | 403) => ("blocked", "verification_apply_forbidden"),
                Some(422) => ("blocked", "verification_apply_rejected"),
                _ => ("error", "verification_apply_failed"),
            };

            serde_json::json!({
                "status": status,
                "reason": reason,
                "persisted": false,
                "target_count": targets.len(),
                "applicable_outcome_count": applicable_outcomes.len(),
                "reverified": report.reverified,
                "stale": report.stale,
                "skipped": report.skipped,
                "outcomes": report.outcomes,
                "apply_error": {
                    "http_status": error.http_status(),
                    "message": error.to_string(),
                },
                "note": "Verification outcomes were computed, but POST /v1/context/verification/apply did not complete successfully.",
            })
        }
    }
}

fn skipped_verification_preview(reason: &str, note: &str) -> Value {
    serde_json::json!({
        "status": "skipped",
        "reason": reason,
        "persisted": false,
        "target_count": 0,
        "reverified": 0,
        "stale": 0,
        "skipped": 0,
        "outcomes": [],
        "note": note,
    })
}

fn build_recent_preview_path(
    session_id: Option<&str>,
    team_id: Option<&str>,
    repo: Option<&str>,
    branch: Option<&str>,
    limit: Option<u64>,
) -> String {
    let mut params = Vec::new();
    if let Some(value) = session_id.filter(|value| !value.trim().is_empty()) {
        params.push(format!("session_id={}", urlencoding::encode(value)));
    }
    if let Some(value) = team_id {
        params.push(format!("team_id={}", urlencoding::encode(value)));
    }
    if let Some(value) = repo {
        params.push(format!("repo={}", urlencoding::encode(value)));
    }
    if let Some(value) = branch {
        params.push(format!("branch={}", urlencoding::encode(value)));
    }
    if let Some(value) = limit {
        params.push(format!("limit={value}"));
    }

    if params.is_empty() {
        return "/v1/context/recent".to_string();
    }

    format!("/v1/context/recent?{}", params.join("&"))
}

fn build_verification_apply_outcomes(outcomes: &[ground_truth::VerificationOutcome]) -> Vec<Value> {
    outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome.decision,
                ground_truth::VerificationDecision::Reverified
                    | ground_truth::VerificationDecision::Stale
            )
        })
        .filter_map(|outcome| {
            Some(serde_json::json!({
                "document_id": outcome.document_id.clone()?,
                "verification_status": outcome.verification_status.clone()?,
                "confidence_score": outcome.confidence_score?,
                "verified_at": outcome.verified_at.clone()?,
            }))
        })
        .collect()
}

fn push_note(notes: &mut Vec<String>, note: String) {
    if !notes.iter().any(|existing| existing == &note) {
        notes.push(note);
    }
}

struct GraphFollowThroughOutcome {
    value: Value,
    repo: Option<String>,
    branch: Option<String>,
    team_id: Option<String>,
    repo_root: Option<PathBuf>,
    verification_ready: bool,
}

impl GraphFollowThroughOutcome {
    fn skipped(value: Value) -> Self {
        Self {
            value,
            repo: None,
            branch: None,
            team_id: None,
            repo_root: None,
            verification_ready: false,
        }
    }

    fn verification_ready(
        value: Value,
        repo: String,
        branch: String,
        team_id: Option<String>,
        repo_root: PathBuf,
    ) -> Self {
        Self {
            value,
            repo: Some(repo),
            branch: Some(branch),
            team_id,
            repo_root: Some(repo_root),
            verification_ready: true,
        }
    }
}

fn resolve_repo_root(working_directory: &Path) -> Result<PathBuf, String> {
    let metadata = fs::metadata(working_directory).map_err(|error| {
        format!(
            "working directory {} is not accessible: {error}",
            working_directory.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "working directory {} is not a directory",
            working_directory.display()
        ));
    }

    let output = Command::new("git")
        .arg("-C")
        .arg(working_directory)
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()
        .map_err(|error| {
            format!(
                "failed to run `git rev-parse --show-toplevel` in {}: {error}",
                working_directory.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!(
                "`git rev-parse --show-toplevel` failed in {} with status {}",
                working_directory.display(),
                output.status
            )
        } else {
            format!(
                "`git rev-parse --show-toplevel` failed in {}: {stderr}",
                working_directory.display()
            )
        });
    }

    let repo_root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if repo_root.is_empty() {
        return Err(format!(
            "`git rev-parse --show-toplevel` returned an empty repo root in {}",
            working_directory.display()
        ));
    }
    Ok(PathBuf::from(repo_root))
}

fn list_changed_commit_files(repo_root: &Path, commit: &str) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("diff-tree")
        .arg("--root")
        .arg("--no-commit-id")
        .arg("--name-only")
        .arg("--diff-filter=ACMRTUXB")
        .arg("-r")
        .arg(commit)
        .output()
        .map_err(|error| {
            format!(
                "failed to run `git diff-tree` for commit {commit} in {}: {error}",
                repo_root.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!(
                "`git diff-tree` failed for commit {commit} in {} with status {}",
                repo_root.display(),
                output.status
            )
        } else {
            format!(
                "`git diff-tree` failed for commit {commit} in {}: {stderr}",
                repo_root.display()
            )
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn is_graph_supported_source_file(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase()),
        Some(extension)
            if matches!(
                extension.as_str(),
                "rs" | "ts" | "tsx" | "js" | "jsx" | "py" | "sql"
            )
    )
}

fn array_len(value: &Value, key: &str) -> usize {
    value.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

fn normalize_registration(value: &Value) -> Value {
    serde_json::json!({
        "registration_id": string_field(value, "registration_id"),
        "history_session_id": string_field(value, "history_session_id"),
        "session_id": string_field(value, "session_id"),
        "team_id": optional_output_string(value, "team_id"),
        "repo": string_field(value, "repo"),
        "branch": string_field(value, "branch"),
        "commit": optional_output_string(value, "commit"),
        "working_directory": optional_output_string(value, "working_directory"),
        "created_at": string_field(value, "created_at"),
        "updated_at": string_field(value, "updated_at"),
    })
}

fn required_string_argument(arguments: &Value, key: &str) -> Result<String, CliError> {
    optional_string_argument(arguments, key)?
        .ok_or_else(|| CliError::user(format!("session_init requires '{key}' parameter")))
}

fn optional_string_argument(arguments: &Value, key: &str) -> Result<Option<String>, CliError> {
    let Some(value) = arguments.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| CliError::user(format!("session_init '{key}' must be a string")))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_string()))
}

fn string_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn optional_output_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}
