// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Closed compile-time registry of public gateway proxy request families.
//!
//! This module is the sole exact-path authority for which public upstream proxy
//! request-family routes the gateway admits as governed families. Each entry
//! binds an exact HTTP method + normalized path to a family id and declares
//! authentication, identity, input policy, output policy, budget, audit,
//! settlement, streaming, transport coverage, and the policy stages the family
//! can enforce on an active chain.
//!
//! Callers MUST invoke [`validate_active_chain_before_dispatch`] before upstream
//! dispatch. Incompatible active-chain stages are rejected; they must never be
//! silently skipped.
//!
//! Router registration and [`REGISTRY`] must stay internally consistent.
//! Prefix matching is intentionally rejected.

/// Public proxy request-family identifiers known to the gateway registry.
///
/// `Audio` remains the transcriptions family id consumed by `policy_registry`
///. Its wire/docs id is `audio_transcriptions`. `AudioSpeech` is the
/// separate text-to-speech family for `POST /v1/audio/speech`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestFamily {
    ChatCompletions,
    Completions,
    Responses,
    Messages,
    Embeddings,
    /// Speech-to-text (`POST /v1/audio/transcriptions`). Wire id: `audio_transcriptions`.
    Audio,
    /// Text-to-speech (`POST /v1/audio/speech`). Wire id: `audio_speech`.
    AudioSpeech,
    Moderation,
}

impl RequestFamily {
    /// Stable wire / docs / capability id for this family.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChatCompletions => "chat_completions",
            Self::Completions => "completions",
            Self::Responses => "responses",
            Self::Messages => "messages",
            Self::Embeddings => "embeddings",
            Self::Audio => "audio_transcriptions",
            Self::AudioSpeech => "audio_speech",
            Self::Moderation => "moderation",
        }
    }
}

impl std::fmt::Display for RequestFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a governance stage is covered for a family today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageCoverage {
    /// Stage runs on the family's admitted path today.
    Enforced,
    /// Stage is only partially applied (reduced / non-parity path).
    Partial,
    /// Stage does not apply to this family/transport combination.
    NotApplicable,
    /// Stage is declared for the family but not yet enforceable as GA.
    Planned,
}

impl StageCoverage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Partial => "partial",
            Self::NotApplicable => "not_applicable",
            Self::Planned => "planned",
        }
    }
}

/// Streaming surface declared for a family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamingCoverage {
    /// No streaming surface for this family.
    None,
    /// Server-Sent Events supported on the HTTP family route.
    Sse,
}

impl StreamingCoverage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Sse => "sse",
        }
    }
}

/// Transport modes a family admits on its registered route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FamilyTransport {
    Json,
    Sse,
    BinaryAudio,
}

impl FamilyTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Sse => "sse",
            Self::BinaryAudio => "binary_audio",
        }
    }
}

// coverage declaration for one registered family route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityCoverage {
    pub authentication: StageCoverage,
    pub identity: StageCoverage,
    pub input_policy: StageCoverage,
    pub output_policy: StageCoverage,
    pub budget: StageCoverage,
    pub audit: StageCoverage,
    pub settlement: StageCoverage,
    pub streaming: StreamingCoverage,
    pub transports: &'static [FamilyTransport],
}

/// Policy-chain stage a request family can enforce.
///
/// These align with declarative chain `stage` values (`pre_request`,
/// `post_request`, `pre_response`). A family that lists a stage here may run
/// chain entries at that stage; a family that omits a stage MUST reject any
/// active-chain entry that requires it before upstream dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupportedPolicyStage {
    PreRequest,
    PostRequest,
    PreResponse,
}

impl SupportedPolicyStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreRequest => "pre_request",
            Self::PostRequest => "post_request",
            Self::PreResponse => "pre_response",
        }
    }

    /// Parse a wire / docs stage id. Accepts underscore or hyphen forms.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "pre_request" | "pre-request" => Some(Self::PreRequest),
            "post_request" | "post-request" => Some(Self::PostRequest),
            "pre_response" | "pre-response" => Some(Self::PreResponse),
            _ => None,
        }
    }
}

impl std::fmt::Display for SupportedPolicyStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One active-chain policy reference used for pre-dispatch compatibility checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveChainStageRef<'a> {
    pub kind: &'a str,
    pub stage: SupportedPolicyStage,
}

/// Stable rejection when an active chain requires an unsupported family stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompatibleActiveChainError {
    pub family: RequestFamily,
    pub policy_kind: String,
    pub required_stage: SupportedPolicyStage,
}

impl IncompatibleActiveChainError {
    pub const CODE: &'static str = "policy.incompatible_active_chain";

    pub fn code(&self) -> &'static str {
        Self::CODE
    }

    pub fn message(&self) -> String {
        format!(
            "active chain policy '{}' requires stage '{}' which family '{}' does not support; refusing dispatch (no silent skip)",
            self.policy_kind,
            self.required_stage.as_str(),
            self.family.as_str()
        )
    }
}

impl std::fmt::Display for IncompatibleActiveChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for IncompatibleActiveChainError {}

/// One exact-path registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryEntry {
    pub family: RequestFamily,
    pub method: &'static str,
    pub path: &'static str,
    pub coverage: CapabilityCoverage,
    /// Exact policy stages this family may enforce on an active chain.
    pub supported_policy_stages: &'static [SupportedPolicyStage],
}

impl RegistryEntry {
    pub fn supports_policy_stage(self, stage: SupportedPolicyStage) -> bool {
        self.supported_policy_stages.contains(&stage)
    }
}

const JSON_ONLY: &[FamilyTransport] = &[FamilyTransport::Json];
const JSON_SSE: &[FamilyTransport] = &[FamilyTransport::Json, FamilyTransport::Sse];
const BINARY_AUDIO: &[FamilyTransport] = &[FamilyTransport::BinaryAudio];

/// Full text-family policy stages (Chat Completions / Responses).
const FULL_TEXT_POLICY_STAGES: &[SupportedPolicyStage] = &[
    SupportedPolicyStage::PreRequest,
    SupportedPolicyStage::PostRequest,
    SupportedPolicyStage::PreResponse,
];

/// Messages admits the same stage ids but coverage remains partial.
const MESSAGES_POLICY_STAGES: &[SupportedPolicyStage] = FULL_TEXT_POLICY_STAGES;

/// Embeddings, audio transcription, audio speech, moderation, and legacy
/// completions: pre-request only. Output / pre-response policies are not
/// applicable and must not be silently skipped.
const REDUCED_MODALITY_POLICY_STAGES: &[SupportedPolicyStage] = &[SupportedPolicyStage::PreRequest];

/// Chat Completions / Responses Phase-1 governed path.
const CHAT_RESPONSES_COVERAGE: CapabilityCoverage = CapabilityCoverage {
    authentication: StageCoverage::Enforced,
    identity: StageCoverage::Enforced,
    input_policy: StageCoverage::Enforced,
    output_policy: StageCoverage::Enforced,
    budget: StageCoverage::Partial,
    audit: StageCoverage::Enforced,
    settlement: StageCoverage::Partial,
    streaming: StreamingCoverage::Sse,
    transports: JSON_SSE,
};

/// Messages: auth + routing today; Chat/Responses policy parity is not claimed.
const MESSAGES_COVERAGE: CapabilityCoverage = CapabilityCoverage {
    authentication: StageCoverage::Enforced,
    identity: StageCoverage::Partial,
    input_policy: StageCoverage::Partial,
    output_policy: StageCoverage::Partial,
    budget: StageCoverage::Partial,
    audit: StageCoverage::Partial,
    settlement: StageCoverage::Partial,
    streaming: StreamingCoverage::Sse,
    transports: JSON_SSE,
};

/// Non-text proxy families: admitted routes with reduced governance surface.
const REDUCED_JSON_COVERAGE: CapabilityCoverage = CapabilityCoverage {
    authentication: StageCoverage::Enforced,
    identity: StageCoverage::Partial,
    input_policy: StageCoverage::Partial,
    output_policy: StageCoverage::NotApplicable,
    budget: StageCoverage::Partial,
    audit: StageCoverage::Partial,
    settlement: StageCoverage::Partial,
    streaming: StreamingCoverage::None,
    transports: JSON_ONLY,
};

const AUDIO_SPEECH_COVERAGE: CapabilityCoverage = CapabilityCoverage {
    authentication: StageCoverage::Enforced,
    identity: StageCoverage::Partial,
    input_policy: StageCoverage::Partial,
    output_policy: StageCoverage::NotApplicable,
    budget: StageCoverage::Partial,
    audit: StageCoverage::Partial,
    settlement: StageCoverage::Partial,
    streaming: StreamingCoverage::None,
    transports: BINARY_AUDIO,
};

/// Authoritative inventory of public proxy request-family routes.
///
/// Exact method + path pairs only. Adjacent surfaces (models discovery,
/// WebSocket, MCP) are intentionally outside this table.
pub static REGISTRY: &[RegistryEntry] = &[
    RegistryEntry {
        family: RequestFamily::ChatCompletions,
        method: "POST",
        path: "/v1/chat/completions",
        coverage: CHAT_RESPONSES_COVERAGE,
        supported_policy_stages: FULL_TEXT_POLICY_STAGES,
    },
    RegistryEntry {
        family: RequestFamily::Completions,
        method: "POST",
        path: "/v1/completions",
        coverage: REDUCED_JSON_COVERAGE,
        supported_policy_stages: REDUCED_MODALITY_POLICY_STAGES,
    },
    RegistryEntry {
        family: RequestFamily::Responses,
        method: "POST",
        path: "/v1/responses",
        coverage: CHAT_RESPONSES_COVERAGE,
        supported_policy_stages: FULL_TEXT_POLICY_STAGES,
    },
    RegistryEntry {
        family: RequestFamily::Messages,
        method: "POST",
        path: "/v1/messages",
        coverage: MESSAGES_COVERAGE,
        supported_policy_stages: MESSAGES_POLICY_STAGES,
    },
    RegistryEntry {
        family: RequestFamily::Embeddings,
        method: "POST",
        path: "/v1/embeddings",
        coverage: REDUCED_JSON_COVERAGE,
        supported_policy_stages: REDUCED_MODALITY_POLICY_STAGES,
    },
    RegistryEntry {
        family: RequestFamily::Audio,
        method: "POST",
        path: "/v1/audio/transcriptions",
        coverage: REDUCED_JSON_COVERAGE,
        supported_policy_stages: REDUCED_MODALITY_POLICY_STAGES,
    },
    RegistryEntry {
        family: RequestFamily::AudioSpeech,
        method: "POST",
        path: "/v1/audio/speech",
        coverage: AUDIO_SPEECH_COVERAGE,
        supported_policy_stages: REDUCED_MODALITY_POLICY_STAGES,
    },
    RegistryEntry {
        family: RequestFamily::Moderation,
        method: "POST",
        path: "/v1/moderations",
        coverage: REDUCED_JSON_COVERAGE,
        supported_policy_stages: REDUCED_MODALITY_POLICY_STAGES,
    },
];

/// Exact-path family resolution. Rejects prefix matches such as `/v1/chat/completions/ws`.
pub fn resolve_family(method: &str, path: &str) -> Option<RequestFamily> {
    resolve_entry(method, path).map(|entry| entry.family)
}

/// Exact-path registry lookup returning the full coverage entry.
pub fn resolve_entry(method: &str, path: &str) -> Option<&'static RegistryEntry> {
    let normalized = normalize_registry_path(path);
    REGISTRY.iter().find(|entry| {
        entry.method.eq_ignore_ascii_case(method) && entry.path == normalized.as_str()
    })
}

/// Normalize a request path the same way registry keys are stored.
pub fn normalize_registry_path(path: &str) -> String {
    let trimmed = path.trim();
    let without_query = trimmed.split('?').next().unwrap_or(trimmed);
    let mut out = String::with_capacity(without_query.len());
    let mut prev_slash = false;
    for ch in without_query.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push(ch);
            }
            prev_slash = true;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// Iterate registered family wire ids in registry order.
pub fn registered_family_ids() -> impl Iterator<Item = &'static str> {
    REGISTRY.iter().map(|entry| entry.family.as_str())
}

/// Iterate exact `(method, path)` pairs in registry order.
pub fn registered_method_paths() -> impl Iterator<Item = (&'static str, &'static str)> {
    REGISTRY.iter().map(|entry| (entry.method, entry.path))
}

/// Look up a registry row by family wire id.
pub fn lookup_by_family_id(family_id: &str) -> Option<&'static RegistryEntry> {
    REGISTRY
        .iter()
        .find(|entry| entry.family.as_str() == family_id)
}

/// Exact supported policy stages for a registered family.
pub fn supported_policy_stages(family: RequestFamily) -> &'static [SupportedPolicyStage] {
    lookup_by_family_id(family.as_str())
        .map(|entry| entry.supported_policy_stages)
        .unwrap_or(&[])
}

/// Returns true when `family` may enforce chain entries at `stage`.
fn family_supports_policy_stage(family: RequestFamily, stage: SupportedPolicyStage) -> bool {
    supported_policy_stages(family).contains(&stage)
}

/// Families whose modality contract limits policy stages to pre-request only
///: embeddings, audio transcription, audio speech, moderation, and
/// legacy completions.
fn reduced_modality_families() -> &'static [RequestFamily] {
    &[
        RequestFamily::Embeddings,
        RequestFamily::Audio,
        RequestFamily::AudioSpeech,
        RequestFamily::Moderation,
        RequestFamily::Completions,
    ]
}

/// Validate that every active-chain entry requires only stages the family
/// supports. Incompatible entries MUST fail closed before upstream dispatch.
///
/// Empty chains are compatible. Compatible pre-request entries on reduced
/// modality families are allowed; pre-response / post-request entries are not.
pub fn validate_active_chain_before_dispatch(
    family: RequestFamily,
    active_chain: &[ActiveChainStageRef<'_>],
) -> Result<(), IncompatibleActiveChainError> {
    let supported = supported_policy_stages(family);
    for entry in active_chain {
        if !supported.contains(&entry.stage) {
            return Err(IncompatibleActiveChainError {
                family,
                policy_kind: entry.kind.to_string(),
                required_stage: entry.stage,
            });
        }
    }
    Ok(())
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
    use std::collections::HashSet;

    #[test]
    fn registry_has_no_duplicate_method_path() {
        let mut seen = HashSet::new();
        for entry in REGISTRY {
            let key = (entry.method, entry.path);
            assert!(
                seen.insert(key),
                "duplicate registry entry: {} {}",
                entry.method,
                entry.path
            );
        }
    }

    #[test]
    fn registry_has_no_duplicate_families() {
        let mut seen = HashSet::new();
        for entry in REGISTRY {
            assert!(
                seen.insert(entry.family),
                "duplicate family: {:?}",
                entry.family
            );
        }
    }

    #[test]
    fn registry_contains_required_families_including_audio_speech() {
        let families: HashSet<RequestFamily> = REGISTRY.iter().map(|e| e.family).collect();
        assert!(families.contains(&RequestFamily::ChatCompletions));
        assert!(families.contains(&RequestFamily::Completions));
        assert!(families.contains(&RequestFamily::Responses));
        assert!(families.contains(&RequestFamily::Messages));
        assert!(families.contains(&RequestFamily::Embeddings));
        assert!(families.contains(&RequestFamily::Audio));
        assert!(families.contains(&RequestFamily::AudioSpeech));
        assert!(families.contains(&RequestFamily::Moderation));
        assert_eq!(
            lookup_by_family_id("audio_transcriptions").map(|e| e.path),
            Some("/v1/audio/transcriptions")
        );
        assert_eq!(
            lookup_by_family_id("audio_speech").map(|e| e.path),
            Some("/v1/audio/speech")
        );
    }

    #[test]
    fn every_entry_declares_req013_coverage() {
        for entry in REGISTRY {
            assert!(!entry.coverage.transports.is_empty(), "{}", entry.path);
            assert!(!entry.family.as_str().is_empty());
            assert!(!entry.method.is_empty());
            assert!(entry.path.starts_with('/'));
            // Stages must be explicitly classified (any StageCoverage variant).
            let _ = entry.coverage.authentication.as_str();
            let _ = entry.coverage.identity.as_str();
            let _ = entry.coverage.input_policy.as_str();
            let _ = entry.coverage.output_policy.as_str();
            let _ = entry.coverage.budget.as_str();
            let _ = entry.coverage.audit.as_str();
            let _ = entry.coverage.settlement.as_str();
            let _ = entry.coverage.streaming.as_str();
        }
    }

    #[test]
    fn resolve_family_is_exact_path_only() {
        assert_eq!(
            resolve_family("POST", "/v1/chat/completions"),
            Some(RequestFamily::ChatCompletions)
        );
        assert_eq!(
            resolve_family("POST", "/v1/chat/completions/"),
            Some(RequestFamily::ChatCompletions)
        );
        assert_eq!(
            resolve_family("POST", "/v1/embeddings"),
            Some(RequestFamily::Embeddings)
        );
        assert_eq!(
            resolve_family("POST", "/v1/audio/speech"),
            Some(RequestFamily::AudioSpeech)
        );
        assert_eq!(
            resolve_family("POST", "/v1/audio/transcriptions"),
            Some(RequestFamily::Audio)
        );
        // Prefix must not steal the websocket surface.
        assert_eq!(resolve_family("POST", "/v1/chat/completions/ws"), None);
        assert_eq!(resolve_family("GET", "/v1/chat/completions"), None);
        assert_eq!(resolve_family("POST", "/v1/unknown"), None);
        assert_eq!(resolve_family("POST", "/v1/unified/chat/completions"), None);
    }

    #[test]
    fn chat_and_responses_declare_enforced_policy_stages() {
        for family_id in ["chat_completions", "responses"] {
            let entry = lookup_by_family_id(family_id).expect("registered");
            assert_eq!(entry.coverage.authentication, StageCoverage::Enforced);
            assert_eq!(entry.coverage.identity, StageCoverage::Enforced);
            assert_eq!(entry.coverage.input_policy, StageCoverage::Enforced);
            assert_eq!(entry.coverage.output_policy, StageCoverage::Enforced);
            assert_eq!(entry.coverage.audit, StageCoverage::Enforced);
            assert_eq!(entry.coverage.streaming, StreamingCoverage::Sse);
            assert_eq!(
                entry.supported_policy_stages,
                [
                    SupportedPolicyStage::PreRequest,
                    SupportedPolicyStage::PostRequest,
                    SupportedPolicyStage::PreResponse,
                ]
            );
        }
    }

    #[test]
    fn reduced_modality_families_enumerate_pre_request_only() {
        for family in reduced_modality_families() {
            let entry = lookup_by_family_id(family.as_str()).expect("registered");
            assert_eq!(
                entry.supported_policy_stages,
                &[SupportedPolicyStage::PreRequest],
                "family {} must enumerate pre_request only",
                family.as_str()
            );
            assert_eq!(
                entry.coverage.output_policy,
                StageCoverage::NotApplicable,
                "family {} output policy must be not_applicable",
                family.as_str()
            );
            assert!(family_supports_policy_stage(
                *family,
                SupportedPolicyStage::PreRequest
            ));
            assert!(!family_supports_policy_stage(
                *family,
                SupportedPolicyStage::PostRequest
            ));
            assert!(!family_supports_policy_stage(
                *family,
                SupportedPolicyStage::PreResponse
            ));
        }
    }

    #[test]
    fn reduced_modality_families_reject_incompatible_active_chain_before_dispatch() {
        for family in reduced_modality_families() {
            // Compatible pre-request chain is admitted (no silent skip of
            // unsupported stages; compatible stages remain valid).
            assert!(validate_active_chain_before_dispatch(
                *family,
                &[ActiveChainStageRef {
                    kind: "pii-detector",
                    stage: SupportedPolicyStage::PreRequest,
                }]
            )
            .is_ok());

            let err = validate_active_chain_before_dispatch(
                *family,
                &[
                    ActiveChainStageRef {
                        kind: "audit-logger",
                        stage: SupportedPolicyStage::PreRequest,
                    },
                    ActiveChainStageRef {
                        kind: "code-sanitizer",
                        stage: SupportedPolicyStage::PreResponse,
                    },
                ],
            )
            .expect_err("pre_response must reject before dispatch");
            assert_eq!(err.code(), IncompatibleActiveChainError::CODE);
            assert_eq!(err.family, *family);
            assert_eq!(err.policy_kind, "code-sanitizer");
            assert_eq!(err.required_stage, SupportedPolicyStage::PreResponse);
            assert!(err.message().contains("no silent skip"));

            let post_err = validate_active_chain_before_dispatch(
                *family,
                &[ActiveChainStageRef {
                    kind: "request-rewriter",
                    stage: SupportedPolicyStage::PostRequest,
                }],
            )
            .expect_err("post_request must reject before dispatch");
            assert_eq!(post_err.required_stage, SupportedPolicyStage::PostRequest);
        }
    }

    #[test]
    fn chat_family_accepts_full_active_chain_stages() {
        let chain = [
            ActiveChainStageRef {
                kind: "prompt-injection",
                stage: SupportedPolicyStage::PreRequest,
            },
            ActiveChainStageRef {
                kind: "request-rewriter",
                stage: SupportedPolicyStage::PostRequest,
            },
            ActiveChainStageRef {
                kind: "code-sanitizer",
                stage: SupportedPolicyStage::PreResponse,
            },
        ];
        assert!(
            validate_active_chain_before_dispatch(RequestFamily::ChatCompletions, &chain).is_ok()
        );
        assert!(validate_active_chain_before_dispatch(RequestFamily::Responses, &chain).is_ok());
    }

    #[test]
    fn empty_active_chain_is_compatible_for_all_families() {
        for entry in REGISTRY {
            assert!(validate_active_chain_before_dispatch(entry.family, &[]).is_ok());
        }
    }

    #[test]
    fn supported_policy_stage_parse_accepts_hyphen_and_underscore() {
        assert_eq!(
            SupportedPolicyStage::parse("pre-response"),
            Some(SupportedPolicyStage::PreResponse)
        );
        assert_eq!(
            SupportedPolicyStage::parse("pre_request"),
            Some(SupportedPolicyStage::PreRequest)
        );
        assert_eq!(SupportedPolicyStage::parse("unknown"), None);
    }
}
