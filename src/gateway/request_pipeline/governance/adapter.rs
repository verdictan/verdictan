// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Family adapters for typed extraction / reconstruction only.
//!
//! Adapters MUST NOT evaluate policy, reserve budget, dispatch upstream, settle
//! usage, or append durable evidence. Those stages belong to
//! [`super::RequestGovernancePipeline`] and its [`super::GovernanceHost`].

use crate::gateway::request_family_registry::RequestFamily;

use super::error::{GovernanceError, GovernanceResult};

/// Opaque raw request bytes and metadata presented to a family adapter.
#[derive(Debug, Clone)]
pub struct RawFamilyRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Opaque reconstructed request ready for host dispatch after governance.
#[derive(Debug, Clone)]
pub struct ReconstructedFamilyRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Family-specific typed view extracted from a raw request.
///
/// Concrete adapters define their own extracted type; the pipeline only
/// requires that extraction and reconstruction are pure structural transforms.
pub trait FamilyRequestAdapter: Send + Sync {
    /// Strongly typed body/view extracted from the raw request.
    type Extracted: Send + Sync + Clone;

    /// Request family this adapter serves.
    fn family(&self) -> RequestFamily;

    /// Extract a typed view from the raw request. No policy or side effects.
    fn extract(&self, raw: &RawFamilyRequest) -> GovernanceResult<Self::Extracted>;

    /// Reconstruct a dispatchable request from the typed view. No policy or
    /// side effects beyond structural rematerialization.
    fn reconstruct(
        &self,
        extracted: &Self::Extracted,
        raw: &RawFamilyRequest,
    ) -> GovernanceResult<ReconstructedFamilyRequest>;
}

/// Minimal JSON-body adapter used by focused pipeline tests and as a reference
/// for family-specific adapters (extract/reconstruct only).
#[derive(Debug, Clone, Copy)]
pub struct JsonBodyAdapter {
    family: RequestFamily,
}

impl JsonBodyAdapter {
    pub const fn new(family: RequestFamily) -> Self {
        Self { family }
    }
}

impl FamilyRequestAdapter for JsonBodyAdapter {
    type Extracted = serde_json::Value;

    fn family(&self) -> RequestFamily {
        self.family
    }

    fn extract(&self, raw: &RawFamilyRequest) -> GovernanceResult<Self::Extracted> {
        if raw.body.is_empty() {
            return Ok(serde_json::json!({}));
        }
        serde_json::from_slice(&raw.body).map_err(|error| {
            GovernanceError::adapter(format!(
                "family {} typed extraction failed: {error}",
                self.family.as_str()
            ))
        })
    }

    fn reconstruct(
        &self,
        extracted: &Self::Extracted,
        raw: &RawFamilyRequest,
    ) -> GovernanceResult<ReconstructedFamilyRequest> {
        let body = serde_json::to_vec(extracted).map_err(|error| {
            GovernanceError::adapter(format!(
                "family {} typed reconstruction failed: {error}",
                self.family.as_str()
            ))
        })?;
        Ok(ReconstructedFamilyRequest {
            method: raw.method.clone(),
            path: raw.path.clone(),
            headers: raw.headers.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_adapter_extracts_and_reconstructs_only() {
        let adapter = JsonBodyAdapter::new(RequestFamily::ChatCompletions);
        let raw = RawFamilyRequest {
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"model":"gpt-test","messages":[]}"#.to_vec(),
        };
        let extracted = adapter.extract(&raw).expect("extract");
        assert_eq!(extracted["model"], "gpt-test");
        let reconstructed = adapter.reconstruct(&extracted, &raw).expect("reconstruct");
        assert_eq!(reconstructed.method, "POST");
        assert_eq!(reconstructed.path, "/v1/chat/completions");
        let round_trip: serde_json::Value =
            serde_json::from_slice(&reconstructed.body).expect("json");
        assert_eq!(round_trip, extracted);
    }
}
