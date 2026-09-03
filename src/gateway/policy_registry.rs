// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Canonical gateway policy registry.
//!
//! This module is the single inventory of policy kinds known to the gateway
//! runtime. Later lanes derive schema, lint, API validation, and evaluation
//! dispatch from these entries. Reporting-only controls are registered here but
//! are never classified as executable enforcement policies.

use crate::gateway::request_family_registry::RequestFamily;

/// Whether a registered policy is enforcement-capable at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyImplementationState {
    /// Evaluated through the chain evaluator (`enforcement::evaluate_policy`).
    Executable,
    /// Enforced by a dedicated pipeline/module path outside the chain match.
    RuntimeManaged,
    /// Compliance/reporting surface only; must not admit as runtime enforcement.
    ReportingOnly,
}

impl PolicyImplementationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::RuntimeManaged => "runtime_managed",
            Self::ReportingOnly => "reporting_only",
        }
    }

    /// Returns true when the policy may enforce a request/response verdict today.
    pub fn is_enforcement_capable(self) -> bool {
        matches!(self, Self::Executable | Self::RuntimeManaged)
    }
}

/// Pipeline stage at which a policy may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyStage {
    PreRequest,
    PostRequest,
    PreResponse,
}

impl PolicyStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreRequest => "pre_request",
            Self::PostRequest => "post_request",
            Self::PreResponse => "pre_response",
        }
    }
}

/// Transport surfaces a policy is compatible with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyTransport {
    Http,
    Sse,
    WebSocket,
}

impl PolicyTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Sse => "sse",
            Self::WebSocket => "websocket",
        }
    }
}

/// Stable reference to the owning evaluator function for a policy kind.
///
/// The string is a module-qualified symbol name used as the dispatch key for
/// schema/lint/runtime wiring. It is not invoked directly from this registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyEvaluatorRef {
    /// Fully qualified evaluator symbol, e.g. `gateway::enforcement::evaluate_pii_detector`.
    pub function: &'static str,
}

impl PolicyEvaluatorRef {
    pub const fn new(function: &'static str) -> Self {
        Self { function }
    }
}

/// One canonical registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyRegistryEntry {
    pub kind: &'static str,
    pub implementation_state: PolicyImplementationState,
    pub stages: &'static [PolicyStage],
    pub families: &'static [RequestFamily],
    pub transports: &'static [PolicyTransport],
    /// JSON Schema pointer under `cli/schema/policy-configuration.schema.json`.
    pub schema_ref: &'static str,
    pub evaluator: PolicyEvaluatorRef,
    /// Stable reason-code / admission error namespace for this policy.
    pub stable_error_code: &'static str,
}

const ALL_FAMILIES: &[RequestFamily] = &[
    RequestFamily::ChatCompletions,
    RequestFamily::Completions,
    RequestFamily::Responses,
    RequestFamily::Messages,
    RequestFamily::Embeddings,
    RequestFamily::Audio,
    RequestFamily::Moderation,
];

const TEXT_FAMILIES: &[RequestFamily] = &[
    RequestFamily::ChatCompletions,
    RequestFamily::Completions,
    RequestFamily::Responses,
    RequestFamily::Messages,
];

const TOOL_FAMILIES: &[RequestFamily] = &[
    RequestFamily::ChatCompletions,
    RequestFamily::Responses,
    RequestFamily::Messages,
];

const ALL_TRANSPORTS: &[PolicyTransport] = &[
    PolicyTransport::Http,
    PolicyTransport::Sse,
    PolicyTransport::WebSocket,
];

const PRE_REQUEST: &[PolicyStage] = &[PolicyStage::PreRequest];
const PRE_RESPONSE: &[PolicyStage] = &[PolicyStage::PreResponse];
const PRE_REQUEST_AND_RESPONSE: &[PolicyStage] =
    &[PolicyStage::PreRequest, PolicyStage::PreResponse];

macro_rules! entry {
    (
        kind = $kind:expr,
        state = $state:ident,
        stages = $stages:expr,
        families = $families:expr,
        schema = $schema:expr,
        evaluator = $evaluator:expr,
        error = $error:expr $(,)?
    ) => {
        PolicyRegistryEntry {
            kind: $kind,
            implementation_state: PolicyImplementationState::$state,
            stages: $stages,
            families: $families,
            transports: ALL_TRANSPORTS,
            schema_ref: $schema,
            evaluator: PolicyEvaluatorRef::new($evaluator),
            stable_error_code: $error,
        }
    };
}

/// Complete canonical inventory: every currently executable policy plus
/// reporting-only controls classified separately via `implementation_state`.
pub static POLICY_REGISTRY: &[PolicyRegistryEntry] = &[
    // ── Chain-evaluated executable policies ───────────────────────────────
    entry!(
        kind = "prompt-injection",
        state = Executable,
        stages = PRE_REQUEST,
        families = TEXT_FAMILIES,
        schema = "#/definitions/PromptInjection",
        evaluator = "gateway::enforcement::evaluate_prompt_injection",
        error = "prompt_injection",
    ),
    entry!(
        kind = "pii-detector",
        state = Executable,
        stages = PRE_REQUEST,
        families = ALL_FAMILIES,
        schema = "#/definitions/PiiDetector",
        evaluator = "gateway::enforcement::evaluate_pii_detector",
        error = "pii",
    ),
    entry!(
        kind = "hipaa-phi-detector",
        state = Executable,
        stages = PRE_REQUEST,
        families = TEXT_FAMILIES,
        schema = "#/definitions/HipaaPhiDetector",
        evaluator = "gateway::enforcement::evaluate_hipaa_phi_detector",
        error = "hipaa_phi",
    ),
    entry!(
        kind = "rbac",
        state = Executable,
        stages = PRE_REQUEST,
        families = ALL_FAMILIES,
        schema = "#/definitions/Rbac",
        evaluator = "policy::evaluator::evaluate_rbac",
        error = "rbac",
    ),
    entry!(
        kind = "agent-firewall",
        state = Executable,
        stages = PRE_REQUEST_AND_RESPONSE,
        families = TOOL_FAMILIES,
        schema = "#/definitions/AgentFirewall",
        evaluator = "gateway::enforcement::evaluate_agent_firewall",
        error = "agent_firewall",
    ),
    entry!(
        kind = "audit-logger",
        state = Executable,
        stages = PRE_REQUEST,
        families = ALL_FAMILIES,
        schema = "#/definitions/AuditLogger",
        evaluator = "gateway::enforcement::evaluate_audit_logger",
        error = "audit_logger",
    ),
    entry!(
        kind = "cjis-mode",
        state = Executable,
        stages = PRE_REQUEST,
        families = ALL_FAMILIES,
        schema = "#/definitions/CjisMode",
        evaluator = "gateway::enforcement::evaluate_cjis_mode",
        error = "cjis",
    ),
    entry!(
        kind = "dlp-filter",
        state = Executable,
        stages = PRE_REQUEST,
        families = ALL_FAMILIES,
        schema = "#/definitions/DlpFilter",
        evaluator = "gateway::enforcement::evaluate_dlp_filter",
        error = "dlp",
    ),
    entry!(
        kind = "safety-filter",
        state = Executable,
        stages = PRE_REQUEST,
        families = TEXT_FAMILIES,
        schema = "#/definitions/SafetyFilter",
        evaluator = "gateway::enforcement::evaluate_safety_filter",
        error = "safety",
    ),
    entry!(
        kind = "student-privacy",
        state = Executable,
        stages = PRE_REQUEST,
        families = TEXT_FAMILIES,
        schema = "#/definitions/StudentPrivacy",
        evaluator = "gateway::enforcement::evaluate_student_privacy",
        error = "student_privacy",
    ),
    entry!(
        kind = "case-privacy",
        state = Executable,
        stages = PRE_REQUEST,
        families = TEXT_FAMILIES,
        schema = "#/definitions/CasePrivacy",
        evaluator = "gateway::enforcement::evaluate_case_privacy",
        error = "case_privacy",
    ),
    entry!(
        kind = "itar-ear-filter",
        state = Executable,
        stages = PRE_REQUEST,
        families = TEXT_FAMILIES,
        schema = "#/definitions/ItarEarFilter",
        evaluator = "gateway::enforcement::evaluate_itar_ear_filter",
        error = "itar_ear",
    ),
    entry!(
        kind = "entity-list-filter",
        state = Executable,
        stages = PRE_REQUEST,
        families = TEXT_FAMILIES,
        schema = "#/definitions/EntityListFilter",
        evaluator = "gateway::enforcement::evaluate_entity_list_filter",
        error = "entity_list",
    ),
    entry!(
        kind = "dual-use-filter",
        state = Executable,
        stages = PRE_REQUEST,
        families = TEXT_FAMILIES,
        schema = "#/definitions/DualUseFilter",
        evaluator = "gateway::enforcement::evaluate_dual_use_filter",
        error = "dual_use",
    ),
    entry!(
        kind = "embedding-detector",
        state = Executable,
        stages = PRE_REQUEST_AND_RESPONSE,
        families = ALL_FAMILIES,
        schema = "#/definitions/EmbeddingDetectorPolicy",
        evaluator = "gateway::enforcement::evaluate_embedding_detector",
        error = "embedding",
    ),
    entry!(
        kind = "data-routing-policy",
        state = Executable,
        stages = PRE_REQUEST,
        families = ALL_FAMILIES,
        schema = "#/definitions/DataRoutingPolicy",
        evaluator = "gateway::enforcement::evaluate_data_routing_policy",
        error = "data-routing-policy",
    ),
    entry!(
        kind = "language-validator",
        state = Executable,
        stages = PRE_REQUEST_AND_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/LanguageValidatorPolicy",
        evaluator = "gateway::enforcement::evaluate_language_validator",
        error = "language-validator",
    ),
    entry!(
        kind = "external-moderation",
        state = Executable,
        stages = PRE_REQUEST_AND_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/ExternalModerationPolicy",
        evaluator = "gateway::enforcement::evaluate_external_moderation",
        error = "external-moderation",
    ),
    entry!(
        kind = "bot-detector",
        state = Executable,
        stages = PRE_REQUEST,
        families = ALL_FAMILIES,
        schema = "#/definitions/BotDetectorPolicy",
        evaluator = "gateway::enforcement::evaluate_bot_detector",
        error = "bot_detector",
    ),
    entry!(
        kind = "content-extractor",
        state = Executable,
        stages = PRE_REQUEST_AND_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/ContentExtractorPolicy",
        evaluator = "gateway::enforcement::evaluate_content_extractor",
        error = "content-extractor",
    ),
    entry!(
        kind = "document-analyzer",
        state = Executable,
        stages = PRE_REQUEST_AND_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/DocumentAnalyzerPolicy",
        evaluator = "gateway::enforcement::evaluate_document_analyzer",
        error = "document-analyzer",
    ),
    entry!(
        kind = "code-sanitizer",
        state = Executable,
        stages = PRE_REQUEST_AND_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/CodeSanitizerPolicy",
        evaluator = "gateway::enforcement::evaluate_code_sanitizer",
        error = "code-sanitizer",
    ),
    entry!(
        kind = "tool-validation",
        state = Executable,
        stages = PRE_REQUEST_AND_RESPONSE,
        families = TOOL_FAMILIES,
        schema = "#/definitions/ToolValidationPolicy",
        evaluator = "gateway::enforcement::evaluate_tool_validation",
        error = "tool_validation",
    ),
    entry!(
        kind = "tool-security",
        state = Executable,
        stages = PRE_REQUEST,
        families = TOOL_FAMILIES,
        schema = "#/definitions/ToolSecurityPolicy",
        evaluator = "gateway::enforcement::evaluate_tool_security",
        error = "tool_security",
    ),
    entry!(
        kind = "tool-budget",
        state = Executable,
        stages = PRE_REQUEST,
        families = TOOL_FAMILIES,
        schema = "#/definitions/ToolBudgetPolicy",
        evaluator = "gateway::enforcement::evaluate_tool_budget",
        error = "tool_budget",
    ),
    entry!(
        kind = "gdpr-compliance",
        state = Executable,
        stages = PRE_REQUEST,
        families = ALL_FAMILIES,
        schema = "#/definitions/GdprCompliancePolicy",
        evaluator = "gateway::gdpr::evaluate_gdpr_compliance",
        error = "gdpr",
    ),
    // ── Runtime-managed executable policies (pipeline modules) ────────────
    entry!(
        kind = "flagged-review",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/FlaggedReview",
        evaluator = "gateway::quality::execute_flagged_review",
        error = "flagged_review",
    ),
    entry!(
        kind = "quality-scorer",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/QualityScorer",
        evaluator = "gateway::quality::evaluate_quality_scorer",
        error = "quality",
    ),
    entry!(
        kind = "human-oversight",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/HumanOversight",
        evaluator = "gateway::request_pipeline::evaluate_human_oversight",
        error = "human_oversight",
    ),
    entry!(
        kind = "citation-verifier",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/CitationVerifier",
        evaluator = "gateway::citation::evaluate_citation_verifier",
        error = "citation",
    ),
    entry!(
        kind = "mnpi-filter",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/MnpiFilter",
        evaluator = "gateway::compliance::evaluate_mnpi_filter",
        error = "mnpi",
    ),
    entry!(
        kind = "financial-compliance",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/FinancialCompliance",
        evaluator = "gateway::compliance::evaluate_financial_compliance",
        error = "financial",
    ),
    entry!(
        kind = "healthcare-compliance",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/HealthcareCompliance",
        evaluator = "gateway::compliance::evaluate_healthcare_compliance",
        error = "healthcare",
    ),
    entry!(
        kind = "legal-privilege",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/LegalPrivilege",
        evaluator = "gateway::compliance::evaluate_legal_privilege",
        error = "legal_privilege",
    ),
    entry!(
        kind = "upl-filter",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/UplFilter",
        evaluator = "gateway::compliance::evaluate_upl_filter",
        error = "upl",
    ),
    entry!(
        kind = "bias-monitor",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/BiasMonitor",
        evaluator = "gateway::compliance::evaluate_bias_monitor",
        error = "bias",
    ),
    entry!(
        kind = "response-rewriter",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/ResponseRewriter",
        evaluator = "gateway::rewrite::evaluate_response_rewriter",
        error = "response_rewriter",
    ),
    entry!(
        kind = "request-rewriter",
        state = RuntimeManaged,
        stages = PRE_RESPONSE,
        families = TEXT_FAMILIES,
        schema = "#/definitions/RequestRewriter",
        evaluator = "gateway::request_rewrite::evaluate_request_rewriter",
        error = "request_rewriter",
    ),
    // ── Reporting-only controls (not runtime enforcement) ─────────────────
    entry!(
        kind = "eu-ai-act",
        state = ReportingOnly,
        stages = PRE_REQUEST,
        families = ALL_FAMILIES,
        schema = "#/definitions/EuAiActPolicy",
        evaluator = "gateway::eu_ai_act::generate_compliance_report",
        error = "policy.reporting_only",
    ),
];

/// Look up a policy by kind string.
pub fn lookup(kind: &str) -> Option<&'static PolicyRegistryEntry> {
    POLICY_REGISTRY.iter().find(|entry| entry.kind == kind)
}

/// Every policy that can enforce a verdict today (executable + runtime-managed).
fn executable_policies() -> impl Iterator<Item = &'static PolicyRegistryEntry> {
    POLICY_REGISTRY
        .iter()
        .filter(|entry| entry.implementation_state.is_enforcement_capable())
}

/// Reporting-only controls that must not be admitted as runtime enforcement.
fn reporting_only_policies() -> impl Iterator<Item = &'static PolicyRegistryEntry> {
    POLICY_REGISTRY
        .iter()
        .filter(|entry| entry.implementation_state == PolicyImplementationState::ReportingOnly)
}

/// Returns true when `kind` is registered as enforcement-capable.
fn is_executable_kind(kind: &str) -> bool {
    lookup(kind)
        .map(|entry| entry.implementation_state.is_enforcement_capable())
        .unwrap_or(false)
}

/// Returns true when `kind` is registered as reporting-only.
fn is_reporting_only_kind(kind: &str) -> bool {
    lookup(kind)
        .map(|entry| entry.implementation_state == PolicyImplementationState::ReportingOnly)
        .unwrap_or(false)
}

/// Default stage for a registered kind, matching current chain defaults:
/// runtime-managed / output-phase kinds default to `pre_response`, others to
/// `pre_request`. Unknown kinds default to `pre_request`.
pub fn default_stage_for_kind(kind: &str) -> PolicyStage {
    match lookup(kind) {
        Some(entry) if entry.implementation_state == PolicyImplementationState::RuntimeManaged => {
            PolicyStage::PreResponse
        }
        Some(entry) => entry
            .stages
            .first()
            .copied()
            .unwrap_or(PolicyStage::PreRequest),
        None => PolicyStage::PreRequest,
    }
}

/// Stable error code for an unsupported / unknown policy kind.
pub const UNSUPPORTED_KIND_ERROR: &str = "policy.unsupported_kind";

/// Stable error code when a reporting-only control appears in a runtime chain.
pub const REPORTING_ONLY_ERROR: &str = "policy.reporting_only";

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::collections::HashSet;

    #[test]
    fn registry_has_unique_kinds() {
        let mut seen = HashSet::new();
        for entry in POLICY_REGISTRY {
            assert!(
                seen.insert(entry.kind),
                "duplicate policy kind in registry: {}",
                entry.kind
            );
        }
    }

    #[test]
    fn registry_entries_have_required_metadata() {
        for entry in POLICY_REGISTRY {
            assert!(!entry.kind.is_empty());
            assert!(!entry.stages.is_empty(), "{} missing stages", entry.kind);
            assert!(
                !entry.families.is_empty(),
                "{} missing families",
                entry.kind
            );
            assert!(
                !entry.transports.is_empty(),
                "{} missing transports",
                entry.kind
            );
            assert!(
                entry.schema_ref.starts_with("#/definitions/"),
                "{} schema_ref must be a definitions pointer",
                entry.kind
            );
            assert!(
                !entry.evaluator.function.is_empty(),
                "{} missing evaluator",
                entry.kind
            );
            assert!(
                !entry.stable_error_code.is_empty(),
                "{} missing stable_error_code",
                entry.kind
            );
        }
    }

    #[test]
    fn executable_inventory_excludes_reporting_only() {
        let executable: HashSet<&str> = executable_policies().map(|e| e.kind).collect();
        let reporting: HashSet<&str> = reporting_only_policies().map(|e| e.kind).collect();

        assert!(executable.contains("prompt-injection"));
        assert!(executable.contains("pii-detector"));
        assert!(executable.contains("quality-scorer"));
        assert!(executable.contains("mnpi-filter"));
        assert!(!executable.contains("eu-ai-act"));

        assert_eq!(reporting, HashSet::from(["eu-ai-act"]));
        assert!(executable.is_disjoint(&reporting));
    }

    #[test]
    fn eu_ai_act_is_reporting_only_with_stable_code() {
        let entry = lookup("eu-ai-act").expect("eu-ai-act registered");
        assert_eq!(
            entry.implementation_state,
            PolicyImplementationState::ReportingOnly
        );
        assert_eq!(entry.stable_error_code, REPORTING_ONLY_ERROR);
        assert_eq!(
            entry.evaluator.function,
            "gateway::eu_ai_act::generate_compliance_report"
        );
        assert!(is_reporting_only_kind("eu-ai-act"));
        assert!(!is_executable_kind("eu-ai-act"));
    }

    #[test]
    fn unknown_kind_is_neither_executable_nor_reporting() {
        assert!(lookup("future-policy").is_none());
        assert!(!is_executable_kind("future-policy"));
        assert!(!is_reporting_only_kind("future-policy"));
    }

    #[test]
    fn default_stage_matches_runtime_managed_vs_chain() {
        assert_eq!(
            default_stage_for_kind("quality-scorer"),
            PolicyStage::PreResponse
        );
        assert_eq!(
            default_stage_for_kind("prompt-injection"),
            PolicyStage::PreRequest
        );
        assert_eq!(
            default_stage_for_kind("unknown-policy"),
            PolicyStage::PreRequest
        );
    }

    #[test]
    fn registry_covers_chain_and_runtime_managed_kinds() {
        let kinds: HashSet<&str> = POLICY_REGISTRY.iter().map(|e| e.kind).collect();
        for kind in [
            "prompt-injection",
            "rbac",
            "cjis-mode",
            "external-moderation",
            "gdpr-compliance",
            "flagged-review",
            "request-rewriter",
            "response-rewriter",
            "eu-ai-act",
        ] {
            assert!(kinds.contains(kind), "missing registry kind: {kind}");
        }
    }
}
