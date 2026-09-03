// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

const AUTO_CAPTURE_SUPPRESSION_SIMILARITY_THRESHOLD: f64 = 0.9;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    Database,
    Code,
    Config,
    ApiContract,
    HumanVerified,
}

impl SourceType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Code => "code",
            Self::Config => "config",
            Self::ApiContract => "api_contract",
            Self::HumanVerified => "human_verified",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedBy {
    System,
    Human,
}

impl VerifiedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Human => "human",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct ProvenanceRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_addressable_ref: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PreparedShareProvenance {
    pub source_type: Option<String>,
    pub source_ref: Option<Value>,
    pub verification_hash: Option<String>,
    pub verified_by: Option<String>,
    pub content_addressable_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictResolutionStrategy {
    NewerWins,
    SourceTypeWins,
    VoteWins,
    BothKept,
    HumanRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictResolutionChoice {
    KeepA,
    KeepB,
    KeepBoth,
    HumanRequired,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConflictCandidate {
    pub source_type: Option<SourceType>,
    pub verification_status: Option<String>,
    pub confidence_score: Option<f64>,
    pub commit_timestamp: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub vote_count: i64,
    pub branch: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentAddressableRef {
    pub commit: String,
    pub path: String,
}

impl ContentAddressableRef {
    pub fn from_parts(commit: &str, path: &str) -> Option<Self> {
        let normalized_commit = commit.trim();
        let normalized_path = path.trim();
        if normalized_commit.is_empty() || normalized_path.is_empty() {
            return None;
        }
        Some(Self {
            commit: normalized_commit.to_string(),
            path: normalized_path.to_string(),
        })
    }

    pub fn parse(value: &str) -> Option<Self> {
        let (commit, path) = value.split_once(':')?;
        Self::from_parts(commit, path)
    }

    pub fn from_source_ref(value: &Value) -> Option<Self> {
        let commit = value
            .get("commit")
            .or_else(|| value.get("commit_sha"))
            .and_then(Value::as_str)?;
        let path = value
            .get("path")
            .or_else(|| value.get("file_path"))
            .and_then(Value::as_str)?;
        Self::from_parts(commit, path)
    }

    pub fn as_spec(&self) -> String {
        format!("{}:{}", self.commit, self.path)
    }
}

pub trait SourceMaterialResolver {
    fn resolve(&self, reference: &ContentAddressableRef) -> Result<Vec<u8>, String>;
}

#[derive(Clone, Debug)]
pub struct GitShowSourceMaterialResolver {
    repo_root: PathBuf,
}

impl GitShowSourceMaterialResolver {
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }
}

impl SourceMaterialResolver for GitShowSourceMaterialResolver {
    fn resolve(&self, reference: &ContentAddressableRef) -> Result<Vec<u8>, String> {
        let spec = reference.as_spec();
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .arg("show")
            .arg(&spec)
            .output()
            .map_err(|error| {
                format!(
                    "failed to run `git show {spec}` in {}: {error}",
                    self.repo_root.display()
                )
            })?;
        if output.status.success() {
            return Ok(output.stdout);
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            Err(format!(
                "`git show {spec}` failed in {} with status {}",
                self.repo_root.display(),
                output.status
            ))
        } else {
            Err(format!(
                "`git show {spec}` failed in {}: {stderr}",
                self.repo_root.display()
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct VerificationTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<SourceType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_addressable_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_verification_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f64>,
}

impl VerificationTarget {
    pub fn resolved_reference(&self) -> Option<ContentAddressableRef> {
        resolve_content_addressable_ref(
            self.source_ref.as_ref(),
            self.content_addressable_ref.as_deref(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationDecision {
    Reverified,
    Stale,
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerificationOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    pub decision: VerificationDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_source_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_verification_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_verification_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_confidence_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub outcomes: Vec<VerificationOutcome>,
    pub reverified: usize,
    pub stale: usize,
    pub skipped: usize,
}

pub fn provenance_for_source_kind(
    source_kind: &str,
    source_ref: Option<Value>,
    source_content: Option<&[u8]>,
    now: DateTime<Utc>,
) -> ProvenanceRecord {
    let mapped_source_type = match source_kind {
        "manual" => Some(SourceType::HumanVerified),
        "tool_result" => Some(SourceType::Database),
        "schema_snapshot" => Some(SourceType::Code),
        "response_capture" => None,
        _ => None,
    };
    let verified_by = match source_kind {
        "manual" => Some(VerifiedBy::Human),
        "tool_result" | "schema_snapshot" => Some(VerifiedBy::System),
        _ => None,
    };
    let verification_hash = source_content
        .filter(|content| !content.is_empty())
        .map(compute_verification_hash);

    ProvenanceRecord {
        source_type: mapped_source_type
            .map(SourceType::as_str)
            .map(str::to_string),
        source_ref: source_ref.clone(),
        verification_hash,
        verified_at: mapped_source_type.map(|_| now.to_rfc3339()),
        verified_by: verified_by.map(VerifiedBy::as_str).map(str::to_string),
        content_addressable_ref: source_ref
            .as_ref()
            .and_then(content_addressable_ref_from_source_ref),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_share_provenance(
    repo: Option<&str>,
    branch: Option<&str>,
    commit: Option<&str>,
    file_path: Option<&str>,
    source_type: Option<&str>,
    source_ref: Option<&Value>,
    verification_hash: Option<&str>,
    verified_by: Option<&str>,
    content_addressable_ref: Option<&str>,
) -> Result<PreparedShareProvenance, String> {
    let mut normalized_source_type = normalize_optional(source_type);
    let mut normalized_verified_by = normalize_optional(verified_by);

    if let Some(value) = normalized_source_type.as_deref() {
        match value {
            "database" | "code" | "config" | "api_contract" | "human_verified" => {}
            _ => {
                return Err(
                    "context_share source_type must be one of: database, code, config, api_contract, human_verified"
                        .to_string(),
                );
            }
        }
    }
    if let Some(value) = normalized_verified_by.as_deref() {
        match value {
            "system" | "human" => {}
            _ => {
                return Err("context_share verified_by must be one of: system, human".to_string());
            }
        }
    }

    let normalized_repo = normalize_optional(repo);
    let normalized_branch = normalize_optional(branch);
    let normalized_commit = normalize_optional(commit);
    let normalized_file_path = normalize_optional(file_path);
    let derived_source_ref = source_ref.cloned().or_else(|| {
        let path = normalized_file_path.clone()?;
        Some(serde_json::json!({
            "reference_kind": "repository_file",
            "commit": normalized_commit,
            "path": path,
            "repo": normalized_repo,
            "branch": normalized_branch,
        }))
    });
    let derived_content_addressable_ref =
        normalize_optional(content_addressable_ref).or_else(|| {
            let commit = normalized_commit.clone()?;
            let path = normalized_file_path.clone()?;
            Some(format!("{commit}:{path}"))
        });
    if normalized_source_type.is_none() && normalized_file_path.is_some() {
        normalized_source_type = Some(SourceType::Code.as_str().to_string());
    }
    if normalized_verified_by.is_none()
        && (derived_source_ref.is_some()
            || derived_content_addressable_ref.is_some()
            || normalize_optional(verification_hash).is_some()
            || normalized_source_type.is_some())
    {
        normalized_verified_by = Some(VerifiedBy::Human.as_str().to_string());
    }

    Ok(PreparedShareProvenance {
        source_type: normalized_source_type,
        source_ref: derived_source_ref,
        verification_hash: normalize_optional(verification_hash),
        verified_by: normalized_verified_by,
        content_addressable_ref: derived_content_addressable_ref,
    })
}

pub fn normalize_document_provenance(document: &Value) -> Value {
    serde_json::json!({
        "available": provenance_available(document),
        "source_kind": optional_output_string(document, "source_kind"),
        "source_type": optional_output_string(document, "source_type"),
        "source_ref": document.get("source_ref").cloned().unwrap_or(Value::Null),
        "verification_hash": optional_output_string(document, "verification_hash"),
        "verified_at": optional_output_string(document, "verified_at"),
        "verified_by": optional_output_string(document, "verified_by"),
        "content_addressable_ref": optional_output_string(document, "content_addressable_ref"),
        "authority_rank": document.get("authority_rank").cloned().unwrap_or(Value::Null),
        "verification_status": optional_output_string(document, "verification_status"),
        "confidence_tier": optional_output_string(document, "confidence_tier"),
        "confidence_score": document.get("confidence_score").cloned().unwrap_or(Value::Null),
        "staleness_indicator": document
            .get("staleness_indicator")
            .cloned()
            .unwrap_or_else(|| derived_staleness_indicator(document)),
        "source_session_id": optional_output_string(document, "history_session_id"),
        "source_user_id": optional_output_string(document, "source_user_id"),
        "source_user_display_name": optional_output_string(document, "source_user_display_name"),
        "capture_timestamp": optional_output_string(document, "created_at"),
        "citation_required": document
            .get("citation_required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

pub fn session_scope_metadata(value: &Value) -> Value {
    serde_json::json!({
        "source_kind": "session_registration",
        "source_type": SourceType::Code.as_str(),
        "source_ref": {
            "reference_kind": "session_git_context",
            "repo": value.get("repo").cloned().unwrap_or(Value::Null),
            "branch": value.get("branch").cloned().unwrap_or(Value::Null),
            "commit": value.get("commit").cloned().unwrap_or(Value::Null),
            "working_directory": value.get("working_directory").cloned().unwrap_or(Value::Null),
        },
        "source_session_id": optional_output_string(value, "history_session_id"),
        "capture_timestamp": optional_output_string(value, "updated_at"),
        "staleness_indicator": if optional_output_string(value, "commit").is_some() {
            Value::String("commit_bound".to_string())
        } else {
            Value::String("commit_unset".to_string())
        },
    })
}

pub fn compute_verification_hash(source_content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_content);
    hex::encode(hasher.finalize())
}

pub fn authority_rank(
    source_type: Option<SourceType>,
    verification_status: Option<&str>,
    confidence_score: Option<f64>,
) -> i32 {
    match source_type {
        Some(SourceType::Database) | Some(SourceType::ApiContract) => 1,
        Some(SourceType::Code) | Some(SourceType::Config) => 2,
        Some(SourceType::HumanVerified)
            if verification_status == Some("verified")
                || confidence_score.unwrap_or_default() >= 0.8 =>
        {
            3
        }
        Some(SourceType::HumanVerified) => 4,
        None => 5,
    }
}

pub fn should_suppress_auto_capture(
    existing_similarity: f64,
    existing_source_type: Option<SourceType>,
    existing_verification_status: Option<&str>,
    existing_confidence_score: Option<f64>,
) -> bool {
    existing_similarity > AUTO_CAPTURE_SUPPRESSION_SIMILARITY_THRESHOLD
        && authority_rank(
            existing_source_type,
            existing_verification_status,
            existing_confidence_score,
        ) < 5
}

pub fn source_type_from_str(value: &str) -> Option<SourceType> {
    match value.trim() {
        "database" => Some(SourceType::Database),
        "code" => Some(SourceType::Code),
        "config" => Some(SourceType::Config),
        "api_contract" => Some(SourceType::ApiContract),
        "human_verified" => Some(SourceType::HumanVerified),
        _ => None,
    }
}

pub fn verification_target_from_document(document: &Value) -> VerificationTarget {
    VerificationTarget {
        document_id: optional_output_string(document, "document_id")
            .or_else(|| optional_output_string(document, "id")),
        source_type: optional_output_string(document, "source_type")
            .as_deref()
            .and_then(source_type_from_str),
        source_ref: document
            .get("source_ref")
            .cloned()
            .filter(|value| !value.is_null()),
        content_addressable_ref: optional_output_string(document, "content_addressable_ref"),
        expected_verification_hash: optional_output_string(document, "verification_hash"),
        verification_status: optional_output_string(document, "verification_status"),
        confidence_score: document.get("confidence_score").and_then(Value::as_f64),
    }
}

pub fn resolve_content_addressable_ref(
    source_ref: Option<&Value>,
    content_addressable_ref: Option<&str>,
) -> Option<ContentAddressableRef> {
    source_ref
        .and_then(ContentAddressableRef::from_source_ref)
        .or_else(|| content_addressable_ref.and_then(ContentAddressableRef::parse))
}

pub fn apply_stale_confidence_penalty(confidence_score: Option<f64>) -> f64 {
    clamp_confidence_score(confidence_score.unwrap_or(1.0) - 0.5)
}

pub fn verify_target<R: SourceMaterialResolver>(
    resolver: &R,
    target: &VerificationTarget,
    now: DateTime<Utc>,
) -> VerificationOutcome {
    let resolved_reference = target.resolved_reference();
    let resolved_source_ref = resolved_reference
        .as_ref()
        .map(ContentAddressableRef::as_spec);

    if !should_verify_source_type(target.source_type) {
        return skipped_verification_outcome(
            target,
            resolved_source_ref,
            "source_type_not_verifiable",
        );
    }

    let Some(reference) = resolved_reference else {
        return skipped_verification_outcome(target, None, "missing_content_addressable_ref");
    };

    let expected_hash = normalize_optional(target.expected_verification_hash.as_deref());
    let Some(expected_hash) = expected_hash else {
        return skipped_verification_outcome(
            target,
            Some(reference.as_spec()),
            "missing_expected_verification_hash",
        );
    };

    let material = match resolver.resolve(&reference) {
        Ok(material) => material,
        Err(error) => {
            return skipped_verification_outcome(target, Some(reference.as_spec()), error);
        }
    };
    let actual_hash = compute_verification_hash(&material);
    let verified_at = now.to_rfc3339();

    if actual_hash == expected_hash {
        return VerificationOutcome {
            document_id: target.document_id.clone(),
            decision: VerificationDecision::Reverified,
            verification_status: Some("verified".to_string()),
            resolved_source_ref: Some(reference.as_spec()),
            expected_verification_hash: Some(expected_hash),
            actual_verification_hash: Some(actual_hash),
            previous_confidence_score: target.confidence_score,
            confidence_score: Some(clamp_confidence_score(
                target.confidence_score.unwrap_or(1.0),
            )),
            verified_at: Some(verified_at),
            reason: None,
        };
    }

    VerificationOutcome {
        document_id: target.document_id.clone(),
        decision: VerificationDecision::Stale,
        verification_status: Some("stale".to_string()),
        resolved_source_ref: Some(reference.as_spec()),
        expected_verification_hash: Some(expected_hash),
        actual_verification_hash: Some(actual_hash),
        previous_confidence_score: target.confidence_score,
        confidence_score: Some(apply_stale_confidence_penalty(target.confidence_score)),
        verified_at: Some(verified_at),
        reason: None,
    }
}

pub fn verify_targets<R: SourceMaterialResolver>(
    resolver: &R,
    targets: &[VerificationTarget],
    now: DateTime<Utc>,
) -> VerificationReport {
    let mut report = VerificationReport::default();
    for target in targets {
        let outcome = verify_target(resolver, target, now);
        match outcome.decision {
            VerificationDecision::Reverified => report.reverified += 1,
            VerificationDecision::Stale => report.stale += 1,
            VerificationDecision::Skipped => report.skipped += 1,
        }
        report.outcomes.push(outcome);
    }
    report
}

pub fn verify_targets_in_repo(
    repo_root: impl AsRef<Path>,
    targets: &[VerificationTarget],
    now: DateTime<Utc>,
) -> VerificationReport {
    let resolver = GitShowSourceMaterialResolver::new(repo_root.as_ref().to_path_buf());
    verify_targets(&resolver, targets, now)
}

pub fn resolve_conflict(
    strategy: ConflictResolutionStrategy,
    candidate_a: &ConflictCandidate,
    candidate_b: &ConflictCandidate,
) -> ConflictResolutionChoice {
    match strategy {
        ConflictResolutionStrategy::NewerWins => {
            if effective_timestamp(candidate_a) >= effective_timestamp(candidate_b) {
                ConflictResolutionChoice::KeepA
            } else {
                ConflictResolutionChoice::KeepB
            }
        }
        ConflictResolutionStrategy::SourceTypeWins => {
            if authority_rank(
                candidate_a.source_type,
                candidate_a.verification_status.as_deref(),
                candidate_a.confidence_score,
            ) <= authority_rank(
                candidate_b.source_type,
                candidate_b.verification_status.as_deref(),
                candidate_b.confidence_score,
            ) {
                ConflictResolutionChoice::KeepA
            } else {
                ConflictResolutionChoice::KeepB
            }
        }
        ConflictResolutionStrategy::VoteWins => {
            if candidate_a.vote_count >= candidate_b.vote_count {
                ConflictResolutionChoice::KeepA
            } else {
                ConflictResolutionChoice::KeepB
            }
        }
        ConflictResolutionStrategy::BothKept => ConflictResolutionChoice::KeepBoth,
        ConflictResolutionStrategy::HumanRequired => ConflictResolutionChoice::HumanRequired,
    }
}

impl PreparedShareProvenance {
    pub fn insert_into_body(&self, body: &mut Map<String, Value>) {
        if let Some(value) = self.source_type.clone() {
            body.insert("source_type".to_string(), Value::String(value));
        }
        if let Some(value) = self.source_ref.clone() {
            body.insert("source_ref".to_string(), value);
        }
        if let Some(value) = self.verification_hash.clone() {
            body.insert("verification_hash".to_string(), Value::String(value));
        }
        if let Some(value) = self.verified_by.clone() {
            body.insert("verified_by".to_string(), Value::String(value));
        }
        if let Some(value) = self.content_addressable_ref.clone() {
            body.insert("content_addressable_ref".to_string(), Value::String(value));
        }
    }
}

fn effective_timestamp(candidate: &ConflictCandidate) -> DateTime<Utc> {
    candidate.commit_timestamp.unwrap_or(candidate.created_at)
}

fn content_addressable_ref_from_source_ref(value: &Value) -> Option<String> {
    ContentAddressableRef::from_source_ref(value).map(|reference| reference.as_spec())
}

fn derived_staleness_indicator(value: &Value) -> Value {
    match optional_output_string(value, "verification_status").as_deref() {
        Some("stale") => Value::String("stale".to_string()),
        Some("disputed") | Some("flagged") => Value::String("disputed".to_string()),
        Some("conflict_pending") => Value::String("conflict_pending".to_string()),
        _ if optional_output_string(value, "confidence_tier").as_deref() == Some("stale") => {
            Value::String("stale".to_string())
        }
        _ => Value::Null,
    }
}

fn provenance_available(value: &Value) -> bool {
    [
        "source_kind",
        "source_type",
        "verification_hash",
        "verified_at",
        "verified_by",
        "content_addressable_ref",
        "history_session_id",
        "source_user_id",
        "source_user_display_name",
        "created_at",
    ]
    .iter()
    .any(|key| value.get(*key).is_some_and(field_has_value))
        || value
            .get("source_ref")
            .is_some_and(|candidate| !candidate.is_null())
        || value
            .get("authority_rank")
            .is_some_and(|candidate| candidate.is_number())
        || value
            .get("confidence_score")
            .is_some_and(|candidate| candidate.is_number())
}

fn field_has_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn clamp_confidence_score(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

fn should_verify_source_type(source_type: Option<SourceType>) -> bool {
    matches!(source_type, Some(SourceType::Code | SourceType::Config))
}

fn skipped_verification_outcome(
    target: &VerificationTarget,
    resolved_source_ref: Option<String>,
    reason: impl Into<String>,
) -> VerificationOutcome {
    VerificationOutcome {
        document_id: target.document_id.clone(),
        decision: VerificationDecision::Skipped,
        verification_status: target.verification_status.clone(),
        resolved_source_ref,
        expected_verification_hash: normalize_optional(
            target.expected_verification_hash.as_deref(),
        ),
        actual_verification_hash: None,
        previous_confidence_score: target.confidence_score,
        confidence_score: target.confidence_score.map(clamp_confidence_score),
        verified_at: None,
        reason: Some(reason.into()),
    }
}

fn optional_output_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}
