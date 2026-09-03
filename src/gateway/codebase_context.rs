// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use axum::http::HeaderMap;
use reqwest::StatusCode;

#[derive(Clone, Debug, Default)]
pub(crate) struct FabricRequestMetadata {
    pub org_id: Option<String>,
    pub repo_id: Option<String>,
    pub codebase_identity_id: Option<String>,
    pub artifact_type: Option<String>,
}

impl FabricRequestMetadata {
    pub(crate) fn has_lookup_scope(&self) -> bool {
        self.org_id
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
            && self.has_lookup_selector()
    }

    fn has_lookup_selector(&self) -> bool {
        self.repo_id
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
            || self
                .codebase_identity_id
                .as_deref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
            || self
                .artifact_type
                .as_deref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
    }
}

#[derive(Clone, Debug, serde::Deserialize)]
pub(crate) struct FabricArtifactSlice {
    pub id: String,
    pub artifact_type: String,
    pub source_digest: String,
    pub payload_uri: String,
    pub payload_sha256: String,
    #[serde(default)]
    pub vector_ref: Option<String>,
    #[serde(default)]
    pub provenance: serde_json::Value,
    #[serde(default)]
    pub freshness_identity: serde_json::Value,
}

impl FabricArtifactSlice {
    pub(crate) fn summary_line(&self) -> String {
        let mut parts = vec![
            format!("id={}", self.id),
            format!("type={}", self.artifact_type),
            format!("source_digest={}", self.source_digest),
            format!("payload_uri={}", self.payload_uri),
        ];
        if let Some(vector_ref) = self.vector_ref.as_deref() {
            parts.push(format!("vector_ref={vector_ref}"));
        }
        parts.join(" ")
    }
}

#[derive(Debug, serde::Deserialize)]
struct FabricArtifactListResponse {
    #[serde(default)]
    items: Vec<FabricArtifactSlice>,
}

#[derive(Debug)]
pub(crate) enum FabricRetrievalError {
    InvalidBaseUrl(String),
    Request(reqwest::Error),
    NonSuccess { status: StatusCode, body: String },
    Decode(reqwest::Error),
}

impl FabricRetrievalError {
    pub(crate) fn is_optional_unavailable(&self) -> bool {
        match self {
            Self::NonSuccess { status, body } => {
                *status == StatusCode::NOT_FOUND
                    || (*status == StatusCode::FORBIDDEN
                        && body.contains("\"auth.insufficient_permissions\""))
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for FabricRetrievalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBaseUrl(error) => {
                write!(f, "fabric retrieval failed: invalid base URL: {error}")
            }
            Self::Request(error) => {
                write!(f, "fabric retrieval request failed: {error}")
            }
            Self::NonSuccess { status, body } => {
                write!(f, "fabric retrieval failed: status={status} body={body}")
            }
            Self::Decode(error) => {
                write!(f, "fabric retrieval decode failed: {error}")
            }
        }
    }
}

impl std::error::Error for FabricRetrievalError {}

pub(crate) fn extract_fabric_request_metadata(
    value: &serde_json::Value,
    headers: &HeaderMap,
    org_id: Option<&str>,
) -> FabricRequestMetadata {
    let verdictan = value.get("verdictan");
    let fabric = verdictan
        .and_then(|item| item.get("context_fabric"))
        .or_else(|| value.get("context_fabric"));

    FabricRequestMetadata {
        org_id: org_id
            .map(ToOwned::to_owned)
            .or_else(|| header_value(headers, "x-verdictan-org-id"))
            .or_else(|| string_field(verdictan, "org_id"))
            .or_else(|| string_field(fabric, "org_id")),
        repo_id: header_value(headers, "x-verdictan-repo-id")
            .or_else(|| header_value(headers, "x-repo-id"))
            .or_else(|| string_field(verdictan, "repo_id"))
            .or_else(|| string_field(fabric, "repo_id")),
        codebase_identity_id: header_value(headers, "x-verdictan-codebase-identity-id")
            .or_else(|| string_field(verdictan, "codebase_identity_id"))
            .or_else(|| string_field(fabric, "codebase_identity_id")),
        artifact_type: header_value(headers, "x-verdictan-fabric-artifact-type")
            .or_else(|| string_field(fabric, "artifact_type")),
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn string_field(value: Option<&serde_json::Value>, field: &str) -> Option<String> {
    value?
        .get(field)
        .and_then(|item| item.as_str())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) async fn retrieve_fabric_slices(
    client: &reqwest::Client,
    api_base_url: &str,
    org_id: &str,
    repo_id: Option<&str>,
    codebase_identity_id: Option<&str>,
    artifact_type: Option<&str>,
) -> Result<Vec<FabricArtifactSlice>, FabricRetrievalError> {
    let mut url = reqwest::Url::parse(&format!(
        "{}/v1/cache/fabric-artifacts",
        api_base_url.trim_end_matches('/')
    ))
    .map_err(|error| FabricRetrievalError::InvalidBaseUrl(error.to_string()))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("org_id", org_id);
        query.append_pair("limit", "25");
        if let Some(repo_id) = repo_id.filter(|value| !value.trim().is_empty()) {
            query.append_pair("repo_id", repo_id);
        }
        if let Some(codebase_identity_id) =
            codebase_identity_id.filter(|value| !value.trim().is_empty())
        {
            query.append_pair("codebase_identity_id", codebase_identity_id);
        }
        if let Some(artifact_type) = artifact_type.filter(|value| !value.trim().is_empty()) {
            query.append_pair("artifact_type", artifact_type);
        }
    }

    let response = client
        .get(url)
        .send()
        .await
        .map_err(FabricRetrievalError::Request)?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(FabricRetrievalError::NonSuccess { status, body });
    }

    Ok(response
        .json::<FabricArtifactListResponse>()
        .await
        .map_err(FabricRetrievalError::Decode)?
        .items)
}

pub(crate) fn inject_fabric_slices_into_request(
    value: &mut serde_json::Value,
    slices: &[FabricArtifactSlice],
) -> bool {
    if slices.is_empty() {
        return false;
    }

    let context_text = build_context_text(slices);
    let provenance = provenance_json(slices);
    merge_context_fabric_metadata(value, provenance);

    if let Some(messages) = value
        .get_mut("messages")
        .and_then(|item| item.as_array_mut())
    {
        messages.insert(
            0,
            serde_json::json!({
                "role": "system",
                "content": context_text,
            }),
        );
        return true;
    }

    if let Some(input) = value.get_mut("input") {
        match input {
            serde_json::Value::String(text) => {
                *text = format!("{context_text}\n\n{text}");
                return true;
            }
            serde_json::Value::Array(items) => {
                items.insert(
                    0,
                    serde_json::json!({
                        "role": "system",
                        "content": [{
                            "type": "input_text",
                            "text": context_text,
                        }],
                    }),
                );
                return true;
            }
            _ => {}
        }
    }

    false
}

pub(crate) fn selected_artifact_ids(slices: &[FabricArtifactSlice]) -> Vec<String> {
    slices.iter().map(|slice| slice.id.clone()).collect()
}

pub(crate) fn selected_source_digests(slices: &[FabricArtifactSlice]) -> Vec<String> {
    let mut digests: Vec<String> = slices
        .iter()
        .map(|slice| slice.source_digest.clone())
        .filter(|value| !value.trim().is_empty())
        .collect();
    digests.sort();
    digests.dedup();
    digests
}

pub(crate) fn freshness_identity(slices: &[FabricArtifactSlice]) -> serde_json::Value {
    serde_json::json!({
        "artifacts": slices
            .iter()
            .map(|slice| serde_json::json!({
                "id": slice.id,
                "artifact_type": slice.artifact_type,
                "source_digest": slice.source_digest,
                "freshness_identity": slice.freshness_identity,
            }))
            .collect::<Vec<_>>(),
    })
}

fn build_context_text(slices: &[FabricArtifactSlice]) -> String {
    let mut lines = Vec::with_capacity(slices.len() + 2);
    lines.push("Codebase Context Fabric".to_string());
    lines.push(
        "Verdictan selected these reusable repository artifacts. Use the artifact metadata for grounding; fetch payloads only through the listed payload_uri when a tool is explicitly available.".to_string(),
    );
    lines.push("Do not infer raw source content from metadata alone.".to_string());
    lines.extend(slices.iter().map(FabricArtifactSlice::summary_line));
    lines.join("\n")
}

fn provenance_json(slices: &[FabricArtifactSlice]) -> serde_json::Value {
    serde_json::json!({
        "selected_artifact_ids": selected_artifact_ids(slices),
        "source_digests": selected_source_digests(slices),
        "artifacts": slices
            .iter()
            .map(|slice| serde_json::json!({
                "id": slice.id,
                "artifact_type": slice.artifact_type,
                "source_digest": slice.source_digest,
                "payload_uri": slice.payload_uri,
                "payload_sha256": slice.payload_sha256,
                "vector_ref": slice.vector_ref,
                "provenance": slice.provenance,
                "freshness_identity": slice.freshness_identity,
            }))
            .collect::<Vec<_>>(),
    })
}

fn merge_context_fabric_metadata(value: &mut serde_json::Value, context_fabric: serde_json::Value) {
    if !value.is_object() {
        return;
    }
    let Some(root) = value.as_object_mut() else {
        return;
    };
    let verdictan = root
        .entry("verdictan")
        .or_insert_with(|| serde_json::json!({}));
    if !verdictan.is_object() {
        *verdictan = serde_json::json!({});
    }
    if let Some(object) = verdictan.as_object_mut() {
        object.insert("context_fabric".to_string(), context_fabric);
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
    use super::{extract_fabric_request_metadata, FabricRequestMetadata, FabricRetrievalError};
    use axum::http::{HeaderMap, HeaderValue};
    use reqwest::StatusCode;
    use serde_json::json;

    #[test]
    fn lookup_scope_requires_org_and_explicit_selector() {
        let metadata = FabricRequestMetadata {
            org_id: Some("00000000-0000-4000-a000-000000000001".to_string()),
            repo_id: None,
            codebase_identity_id: None,
            artifact_type: None,
        };
        assert!(
            !metadata.has_lookup_scope(),
            "org-scoped requests alone should not trigger fabric lookup"
        );

        let metadata = FabricRequestMetadata {
            repo_id: Some("api".to_string()),
            ..metadata.clone()
        };
        assert!(metadata.has_lookup_scope());
    }

    #[test]
    fn metadata_extraction_only_enables_lookup_when_selectors_are_present() {
        let empty_headers = HeaderMap::new();
        let plain_request = json!({
            "model": "gpt-5.4-mini",
            "messages": [{"role": "user", "content": "hello"}]
        });
        let metadata = extract_fabric_request_metadata(
            &plain_request,
            &empty_headers,
            Some("00000000-0000-4000-a000-000000000001"),
        );
        assert!(!metadata.has_lookup_scope());

        let mut repo_headers = HeaderMap::new();
        repo_headers.insert("x-verdictan-repo-id", HeaderValue::from_static("api"));
        let metadata = extract_fabric_request_metadata(
            &plain_request,
            &repo_headers,
            Some("00000000-0000-4000-a000-000000000001"),
        );
        assert!(metadata.has_lookup_scope());

        let explicit_request = json!({
            "verdictan": {
                "context_fabric": {
                    "codebase_identity_id": "00000000-0000-4000-a000-000000000099"
                }
            }
        });
        let metadata = extract_fabric_request_metadata(
            &explicit_request,
            &empty_headers,
            Some("00000000-0000-4000-a000-000000000001"),
        );
        assert!(metadata.has_lookup_scope());
    }

    #[test]
    fn lookup_scope_requires_both_org_and_selector() {
        let no_org = FabricRequestMetadata {
            org_id: None,
            repo_id: Some("repo".to_string()),
            codebase_identity_id: None,
            artifact_type: None,
        };
        assert!(!no_org.has_lookup_scope());
    }

    #[test]
    fn lookup_scope_with_codebase_identity_id() {
        let metadata = FabricRequestMetadata {
            org_id: Some("org-1".to_string()),
            repo_id: None,
            codebase_identity_id: Some("cid-1".to_string()),
            artifact_type: None,
        };
        assert!(metadata.has_lookup_scope());
    }

    #[test]
    fn lookup_scope_with_artifact_type() {
        let metadata = FabricRequestMetadata {
            org_id: Some("org-1".to_string()),
            repo_id: None,
            codebase_identity_id: None,
            artifact_type: Some("graph".to_string()),
        };
        assert!(metadata.has_lookup_scope());
    }

    #[test]
    fn lookup_scope_empty_org_fails() {
        let metadata = FabricRequestMetadata {
            org_id: Some("  ".to_string()),
            repo_id: Some("repo".to_string()),
            codebase_identity_id: None,
            artifact_type: None,
        };
        assert!(!metadata.has_lookup_scope());
    }

    #[test]
    fn lookup_scope_empty_selectors_fail() {
        let metadata = FabricRequestMetadata {
            org_id: Some("org-1".to_string()),
            repo_id: Some("  ".to_string()),
            codebase_identity_id: Some("".to_string()),
            artifact_type: None,
        };
        assert!(!metadata.has_lookup_scope());
    }

    #[test]
    fn fabric_artifact_slice_summary_line_without_vector_ref() {
        let slice = super::FabricArtifactSlice {
            id: "art-1".to_string(),
            artifact_type: "graph".to_string(),
            source_digest: "sha256:abc".to_string(),
            payload_uri: "s3://bucket/key".to_string(),
            payload_sha256: "deadbeef".to_string(),
            vector_ref: None,
            provenance: serde_json::json!({}),
            freshness_identity: serde_json::json!({}),
        };
        let line = slice.summary_line();
        assert!(line.contains("id=art-1"));
        assert!(line.contains("type=graph"));
        assert!(line.contains("source_digest=sha256:abc"));
        assert!(line.contains("payload_uri=s3://bucket/key"));
        assert!(!line.contains("vector_ref"));
    }

    #[test]
    fn fabric_artifact_slice_summary_line_with_vector_ref() {
        let slice = super::FabricArtifactSlice {
            id: "art-2".to_string(),
            artifact_type: "embedding".to_string(),
            source_digest: "sha256:def".to_string(),
            payload_uri: "s3://bucket/emb".to_string(),
            payload_sha256: "cafebabe".to_string(),
            vector_ref: Some("collection:ns".to_string()),
            provenance: serde_json::json!({}),
            freshness_identity: serde_json::json!({}),
        };
        let line = slice.summary_line();
        assert!(line.contains("vector_ref=collection:ns"));
    }

    #[test]
    fn fabric_retrieval_error_display_all_variants() {
        let inv = FabricRetrievalError::InvalidBaseUrl("bad url".to_string());
        assert!(inv.to_string().contains("invalid base URL"));

        let non_success = FabricRetrievalError::NonSuccess {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: "error".to_string(),
        };
        assert!(non_success.to_string().contains("500"));
    }

    #[test]
    fn fabric_retrieval_error_is_optional_unavailable_forbidden_without_marker() {
        let forbidden = FabricRetrievalError::NonSuccess {
            status: StatusCode::FORBIDDEN,
            body: "access denied".to_string(),
        };
        assert!(!forbidden.is_optional_unavailable());
    }

    #[test]
    fn selected_artifact_ids_returns_ids() {
        let slices = vec![
            super::FabricArtifactSlice {
                id: "a".to_string(),
                artifact_type: "graph".to_string(),
                source_digest: "d1".to_string(),
                payload_uri: "u1".to_string(),
                payload_sha256: "h1".to_string(),
                vector_ref: None,
                provenance: serde_json::json!({}),
                freshness_identity: serde_json::json!({}),
            },
            super::FabricArtifactSlice {
                id: "b".to_string(),
                artifact_type: "emb".to_string(),
                source_digest: "d2".to_string(),
                payload_uri: "u2".to_string(),
                payload_sha256: "h2".to_string(),
                vector_ref: None,
                provenance: serde_json::json!({}),
                freshness_identity: serde_json::json!({}),
            },
        ];
        assert_eq!(
            super::selected_artifact_ids(&slices),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn selected_source_digests_deduplicates_and_sorts() {
        let slices = vec![
            super::FabricArtifactSlice {
                id: "a".to_string(),
                artifact_type: "g".to_string(),
                source_digest: "d2".to_string(),
                payload_uri: "u".to_string(),
                payload_sha256: "h".to_string(),
                vector_ref: None,
                provenance: serde_json::json!({}),
                freshness_identity: serde_json::json!({}),
            },
            super::FabricArtifactSlice {
                id: "b".to_string(),
                artifact_type: "g".to_string(),
                source_digest: "d1".to_string(),
                payload_uri: "u".to_string(),
                payload_sha256: "h".to_string(),
                vector_ref: None,
                provenance: serde_json::json!({}),
                freshness_identity: serde_json::json!({}),
            },
            super::FabricArtifactSlice {
                id: "c".to_string(),
                artifact_type: "g".to_string(),
                source_digest: "d2".to_string(),
                payload_uri: "u".to_string(),
                payload_sha256: "h".to_string(),
                vector_ref: None,
                provenance: serde_json::json!({}),
                freshness_identity: serde_json::json!({}),
            },
        ];
        assert_eq!(
            super::selected_source_digests(&slices),
            vec!["d1".to_string(), "d2".to_string()]
        );
    }

    #[test]
    fn selected_source_digests_skips_empty() {
        let slices = vec![super::FabricArtifactSlice {
            id: "a".to_string(),
            artifact_type: "g".to_string(),
            source_digest: "  ".to_string(),
            payload_uri: "u".to_string(),
            payload_sha256: "h".to_string(),
            vector_ref: None,
            provenance: serde_json::json!({}),
            freshness_identity: serde_json::json!({}),
        }];
        assert!(super::selected_source_digests(&slices).is_empty());
    }

    #[test]
    fn freshness_identity_returns_artifact_array() {
        let slices = vec![super::FabricArtifactSlice {
            id: "a".to_string(),
            artifact_type: "graph".to_string(),
            source_digest: "d1".to_string(),
            payload_uri: "u1".to_string(),
            payload_sha256: "h1".to_string(),
            vector_ref: None,
            provenance: serde_json::json!({"source": "git"}),
            freshness_identity: serde_json::json!({"commit": "abc"}),
        }];
        let fi = super::freshness_identity(&slices);
        let artifacts = fi["artifacts"].as_array().unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0]["id"], "a");
        assert_eq!(artifacts[0]["freshness_identity"]["commit"], "abc");
    }

    #[test]
    fn inject_fabric_slices_empty_returns_false() {
        let mut req = json!({"messages": [{"role": "user", "content": "hi"}]});
        assert!(!super::inject_fabric_slices_into_request(&mut req, &[]));
    }

    #[test]
    fn inject_fabric_slices_into_messages() {
        let slice = super::FabricArtifactSlice {
            id: "a".to_string(),
            artifact_type: "graph".to_string(),
            source_digest: "d".to_string(),
            payload_uri: "u".to_string(),
            payload_sha256: "h".to_string(),
            vector_ref: None,
            provenance: serde_json::json!({}),
            freshness_identity: serde_json::json!({}),
        };
        let mut req = json!({"messages": [{"role": "user", "content": "hi"}]});
        assert!(super::inject_fabric_slices_into_request(&mut req, &[slice]));
        let messages = req["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert!(messages[0]["content"]
            .as_str()
            .unwrap()
            .contains("Codebase Context Fabric"));
        assert!(req["verdictan"]["context_fabric"].is_object());
    }

    #[test]
    fn inject_fabric_slices_into_string_input() {
        let slice = super::FabricArtifactSlice {
            id: "a".to_string(),
            artifact_type: "g".to_string(),
            source_digest: "d".to_string(),
            payload_uri: "u".to_string(),
            payload_sha256: "h".to_string(),
            vector_ref: None,
            provenance: serde_json::json!({}),
            freshness_identity: serde_json::json!({}),
        };
        let mut req = json!({"input": "user question"});
        assert!(super::inject_fabric_slices_into_request(&mut req, &[slice]));
        let input = req["input"].as_str().unwrap();
        assert!(input.contains("Codebase Context Fabric"));
        assert!(input.contains("user question"));
    }

    #[test]
    fn inject_fabric_slices_into_array_input() {
        let slice = super::FabricArtifactSlice {
            id: "a".to_string(),
            artifact_type: "g".to_string(),
            source_digest: "d".to_string(),
            payload_uri: "u".to_string(),
            payload_sha256: "h".to_string(),
            vector_ref: None,
            provenance: serde_json::json!({}),
            freshness_identity: serde_json::json!({}),
        };
        let mut req = json!({"input": [{"role": "user", "content": "hi"}]});
        assert!(super::inject_fabric_slices_into_request(&mut req, &[slice]));
        let input = req["input"].as_array().unwrap();
        assert_eq!(input.len(), 2);
        assert_eq!(input[0]["role"], "system");
    }

    #[test]
    fn inject_fabric_slices_no_messages_or_input_returns_false() {
        let slice = super::FabricArtifactSlice {
            id: "a".to_string(),
            artifact_type: "g".to_string(),
            source_digest: "d".to_string(),
            payload_uri: "u".to_string(),
            payload_sha256: "h".to_string(),
            vector_ref: None,
            provenance: serde_json::json!({}),
            freshness_identity: serde_json::json!({}),
        };
        let mut req = json!({"model": "gpt-4"});
        assert!(!super::inject_fabric_slices_into_request(
            &mut req,
            &[slice]
        ));
    }

    #[test]
    fn metadata_extraction_from_body_context_fabric() {
        let empty_headers = HeaderMap::new();
        let request = json!({
            "context_fabric": {
                "org_id": "org-direct",
                "repo_id": "repo-direct"
            }
        });
        let metadata = extract_fabric_request_metadata(&request, &empty_headers, None);
        assert_eq!(metadata.org_id.as_deref(), Some("org-direct"));
        assert_eq!(metadata.repo_id.as_deref(), Some("repo-direct"));
    }

    #[test]
    fn metadata_extraction_header_priority_over_body() {
        let mut headers = HeaderMap::new();
        headers.insert("x-verdictan-repo-id", "header-repo".parse().unwrap());
        let request = json!({
            "verdictan": { "repo_id": "body-repo" }
        });
        let metadata = extract_fabric_request_metadata(&request, &headers, Some("org-1"));
        assert_eq!(metadata.repo_id.as_deref(), Some("header-repo"));
    }

    #[test]
    fn metadata_extraction_x_repo_id_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert("x-repo-id", "fallback-repo".parse().unwrap());
        let request = json!({});
        let metadata = extract_fabric_request_metadata(&request, &headers, None);
        assert_eq!(metadata.repo_id.as_deref(), Some("fallback-repo"));
    }

    #[test]
    fn permission_denials_are_treated_as_optional_unavailability() {
        let forbidden = FabricRetrievalError::NonSuccess {
            status: StatusCode::FORBIDDEN,
            body: "{\"error\":{\"code\":\"auth.insufficient_permissions\"}}".to_string(),
        };
        assert!(forbidden.is_optional_unavailable());

        let not_found = FabricRetrievalError::NonSuccess {
            status: StatusCode::NOT_FOUND,
            body: String::new(),
        };
        assert!(not_found.is_optional_unavailable());

        let other = FabricRetrievalError::NonSuccess {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            body: "{\"error\":{\"code\":\"validation.failed\"}}".to_string(),
        };
        assert!(!other.is_optional_unavailable());
    }
}
