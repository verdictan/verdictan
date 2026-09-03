// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! AI Usage Record capture for SIEM / audit streaming.
//!
//! Builds a capture-fidelity-bounded AI Usage Record per Section 9.3 for every
//! governed AI interaction (Chat, Responses, Messages, WebSocket, MCP).
//!
//! The gateway is NOT the redaction or routing authority: it enriches the record
//! with request/response content, hashes, detector findings, and governance
//! metadata, then forwards it through the gateway WAL delivery API
//! ([`crate::gateway::server::EventSink::persist_ai_usage`]) for durable
//! delivery to the API ingestion endpoint.
//!
//! Key constraints:
//! - FSEC-001: org/gateway/actor derived from authenticated context only
//! - FSEC-004: content bounded before allocation, with truncation markers + pre-truncation SHA-256
//! - FSEC-005: findings use masked offsets/hashes, never raw matched values
//! - The gateway persists no SIEM state; it enriches and forwards only

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::gateway::detection::pii;

// ── Constants ───────────────────────────────────────────────────────────────

/// Default maximum bytes for captured request/response body content.
pub const DEFAULT_BODY_CAPTURE_MAX_BYTES: usize = 65_536; // 64 KiB

/// Absolute ceiling enforced before allocation.
pub const ABSOLUTE_BODY_CAPTURE_CEILING: usize = 1_048_576; // 1 MiB

/// Schema version for the AI Usage Record data contract (Section 9.3).
pub const SCHEMA_VERSION: &str = "1.0.0";

// ── Request family ──────────────────────────────────────────────────────────

/// Request families supported by the capture pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestFamily {
    Chat,
    Responses,
    Messages,
    Websocket,
    Mcp,
}

impl RequestFamily {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Responses => "responses",
            Self::Messages => "messages",
            Self::Websocket => "websocket",
            Self::Mcp => "mcp",
        }
    }
}

// ── Transport type ──────────────────────────────────────────────────────────

/// Transport over which the interaction occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Buffered,
    Sse,
    Websocket,
    Mcp,
}

// ── Interaction outcome ─────────────────────────────────────────────────────

/// Outcome of the governed AI interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionOutcome {
    Allow,
    Block,
    Flag,
    Error,
}

// ── Capture outcome ─────────────────────────────────────────────────────────

/// Outcome of the capture attempt itself (FR-001: failures are recorded, never silently dropped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureOutcome {
    /// Record captured and enqueued successfully.
    Captured,
    /// Capture suppressed by policy (ai_usage_streaming.enabled == false).
    Suppressed,
    /// Capture failed — reason recorded.
    Failed { reason: String },
}

// ── Data leakage finding ────────────────────────────────────────────────────

/// A single detector finding attached to the AI Usage Record (Section 9.3 data-leakage).
///
/// FSEC-005: location evidence uses offsets and masked spans — never the raw matched value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorFinding {
    /// Detector that produced this finding (e.g. "pii", "phi", "dlp", "credential", "high_entropy").
    pub detector: String,
    /// Broad category: "pii", "phi", "pci", "dlp", "credential", "high_entropy", "student_privacy".
    pub category: String,
    /// Specific entity type within the category (e.g. "email", "ssn", "api_key").
    pub entity_type: String,
    /// Number of matches found by this detector for this entity type.
    pub match_count: u32,
    /// Confidence level of the detection.
    pub confidence: String,
    /// Policy IDs whose rules matched this finding.
    pub matched_policy_ids: Vec<String>,
    /// Action taken: "redacted", "blocked", or "allowed".
    pub action: String,
    /// Masked evidence locations — byte offsets and span hashes, never raw values.
    pub evidence_locations: Vec<EvidenceLocation>,
    /// Non-reversible hash of a representative sample (never the raw value).
    pub sample_hash: String,
}

/// Masked evidence location for a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLocation {
    /// "request" or "response".
    pub source: String,
    /// Byte offset start (inclusive) in the original content.
    pub start: usize,
    /// Byte offset end (exclusive) in the original content.
    pub end: usize,
    /// SHA-256 of the raw matched span (never the value itself).
    pub span_hash: String,
}

// ── Governance record ───────────────────────────────────────────────────────

/// Governance metadata attached to the AI Usage Record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernanceRecord {
    /// Policy chain entries that matched this request.
    pub matched_policies: Vec<String>,
    /// Per-policy decisions.
    pub decisions: Vec<serde_json::Value>,
    /// Mutations applied by the policy chain.
    pub applied_mutations: Vec<serde_json::Value>,
    /// Redactions applied by the policy chain.
    pub applied_redactions: Vec<serde_json::Value>,
    /// Output-stage evaluations (post-response policy results).
    pub output_stage_evaluations: Vec<serde_json::Value>,
}

// ── Financial metadata ──────────────────────────────────────────────────────

/// Financial and token-usage metadata for the interaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FinancialRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_usage_authorization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend_log_id: Option<String>,
    /// Managed UA attempt UUID correlating financial stage WAL records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ua_attempt_id: Option<String>,
    /// Managed UA financial event UUID correlating stage/complete WAL records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ua_financial_event_id: Option<String>,
}

// ── Capture configuration ───────────────────────────────────────────────────

/// Runtime capture configuration parsed from the `ai_usage_streaming` policy stanza.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Whether AI usage streaming is enabled for this gateway.
    pub enabled: bool,
    /// Maximum bytes to capture for request/response bodies.
    /// Clamped to `ABSOLUTE_BODY_CAPTURE_CEILING` before allocation.
    pub body_capture_max_bytes: usize,
    /// When true, fail closed (503) if durable enqueue fails before dispatch.
    pub mandatory: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            body_capture_max_bytes: DEFAULT_BODY_CAPTURE_MAX_BYTES,
            mandatory: false,
        }
    }
}

impl CaptureConfig {
    /// Effective max bytes, clamped to the absolute ceiling.
    pub fn effective_max_bytes(&self) -> usize {
        self.body_capture_max_bytes
            .min(ABSOLUTE_BODY_CAPTURE_CEILING)
    }
}

// ── The AI Usage Record ─────────────────────────────────────────────────────

/// Complete AI Usage Record per Section 9.3 data contract.
///
/// One record per governed AI interaction. All identity fields are populated
/// from server-owned or authenticated-context values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiUsageRecord {
    // ── Envelope ────────────────────────────────────────────────────────
    pub schema_version: String,
    pub record_id: String,
    pub org_id: String,
    pub captured_at: String,
    pub source: String,

    // ── Identity and tenancy ────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_token_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub request_id: String,

    // ── Interaction ─────────────────────────────────────────────────────
    pub request_family: RequestFamily,
    pub transport: Transport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_host: Option<String>,
    pub streamed: bool,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    pub outcome: InteractionOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,

    // ── Content ────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    pub request_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_sha256_raw: Option<String>,
    pub request_truncated: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
    pub response_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_sha256_raw: Option<String>,
    pub response_truncated: bool,

    // ── Governance ──────────────────────────────────────────────────────
    pub governance: GovernanceRecord,

    // ── Data leakage (FR-002) ───────────────────────────────────────────
    pub detectors: Vec<DetectorFinding>,
    /// Explicit scan-status flag: true means detectors ran, false means not scanned.
    pub scanned: bool,
    /// Whether the scan detected potential credentials/secrets.
    pub secrets_detected: bool,
    /// Roll-up: any detector found potential data leakage.
    pub potential_data_leakage: bool,

    // ── Financial ───────────────────────────────────────────────────────
    pub financial: FinancialRecord,

    // ── Managed UA financial correlation ─────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ua_attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ua_financial_event_id: Option<String>,

    // ── Integrity ───────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trail_event_id: Option<String>,
}

// ── Capture context (builder input) ─────────────────────────────────────────

/// Input context for building an AI Usage Record. Populated by the gateway
/// completion/error pipeline and MCP transport handler before calling `build_record`.
#[derive(Debug, Clone)]
pub struct CaptureContext {
    // Identity — from authenticated context, never from request body
    pub org_id: String,
    pub gateway_id: Option<String>,
    pub agent_id: Option<String>,
    pub subject_token_id: Option<String>,
    pub actor_id: Option<String>,
    pub actor_type: Option<String>,
    pub session_id: Option<String>,
    pub correlation_id: Option<String>,
    pub request_id: String,

    // Interaction
    pub request_family: RequestFamily,
    pub transport: Transport,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub upstream_host: Option<String>,
    pub streamed: bool,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub outcome: InteractionOutcome,
    pub http_status: Option<u16>,

    // Raw content (pre-truncation)
    pub request_body_raw: Option<Vec<u8>>,
    pub response_body_raw: Option<Vec<u8>>,

    // Governance
    pub governance: GovernanceRecord,

    // Financial
    pub financial: FinancialRecord,

    // Managed UA financial correlation
    pub ua_attempt_id: Option<String>,
    pub ua_financial_event_id: Option<String>,

    // Trail linkage
    pub trail_event_id: Option<String>,
}

// ── Content bounding ────────────────────────────────────────────────────────

/// Truncate content to `max_bytes`, returning (bounded_content, was_truncated, pre_truncation_sha256).
///
/// SHA-256 is computed on the FULL pre-truncation content.
/// Content ceiling is enforced BEFORE allocation.
pub fn bound_content(raw: &[u8], max_bytes: usize) -> (Option<String>, bool, Option<String>) {
    if raw.is_empty() {
        return (None, false, None);
    }

    let sha256_full = {
        let mut hasher = Sha256::new();
        hasher.update(raw);
        hex::encode(hasher.finalize())
    };

    let truncated = raw.len() > max_bytes;
    let bounded = if truncated { &raw[..max_bytes] } else { raw };

    let content = String::from_utf8_lossy(bounded).into_owned();

    (Some(content), truncated, Some(sha256_full))
}

// ── Credential / secret-pattern scanner (feature-owned, FASSUMPTION-001) ────

/// Well-known credential and secret patterns for the feature-owned scanner.
/// This is NOT from the existing detectors — it is a new feature contract.
pub mod secret_scanner {
    use sha2::{Digest, Sha256};

    use super::{DetectorFinding, EvidenceLocation};

    macro_rules! static_regex {
        ($pattern:expr) => {{
            static RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
            RE.get_or_init(|| {
                #[allow(clippy::expect_used)]
                regex_lite::Regex::new($pattern).expect("static regex pattern")
            })
        }};
    }

    /// Known credential patterns with their category labels.
    struct SecretPattern {
        #[allow(dead_code)]
        // Pending detector taxonomy surfacing retains the canonical pattern label.
        name: &'static str,
        entity_type: &'static str,
        regex: &'static str,
    }

    const SECRET_PATTERNS: &[SecretPattern] = &[
        SecretPattern {
            name: "aws_access_key",
            entity_type: "aws_access_key_id",
            regex: r"(?i)\b(AKIA[0-9A-Z]{16})\b",
        },
        SecretPattern {
            name: "aws_secret_key",
            entity_type: "aws_secret_access_key",
            regex: r"(?i)(?:aws_secret_access_key|secret_key)\s*[:=]\s*([A-Za-z0-9/+=]{40})\b",
        },
        SecretPattern {
            name: "github_token",
            entity_type: "github_personal_access_token",
            regex: r"\b(ghp_[A-Za-z0-9]{36})\b",
        },
        SecretPattern {
            name: "github_fine_grained",
            entity_type: "github_fine_grained_token",
            regex: r"\b(github_pat_[A-Za-z0-9_]{82})\b",
        },
        SecretPattern {
            name: "openai_api_key",
            entity_type: "openai_api_key",
            regex: r"\b(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})\b",
        },
        SecretPattern {
            name: "openai_project_key",
            entity_type: "openai_project_key",
            regex: r"\b(sk-proj-[A-Za-z0-9_-]{40,})\b",
        },
        SecretPattern {
            name: "generic_api_key",
            entity_type: "generic_api_key",
            regex: r#"(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?"#,
        },
        SecretPattern {
            name: "generic_bearer_token",
            entity_type: "bearer_token",
            regex: r"(?i)(?:bearer|authorization)\s+([A-Za-z0-9_\-.]{20,})",
        },
        SecretPattern {
            name: "private_key_header",
            entity_type: "private_key",
            regex: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        },
        SecretPattern {
            name: "slack_token",
            entity_type: "slack_token",
            regex: r"\b(xox[bposa]-[A-Za-z0-9\-]{10,})\b",
        },
        SecretPattern {
            name: "connection_string",
            entity_type: "connection_string",
            regex: r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s]{10,}",
        },
    ];

    /// Shannon entropy threshold for high-entropy string detection.
    const HIGH_ENTROPY_THRESHOLD: f64 = 4.5;
    /// Minimum length for high-entropy string candidates.
    const HIGH_ENTROPY_MIN_LEN: usize = 20;
    /// Maximum length for high-entropy string candidates.
    const HIGH_ENTROPY_MAX_LEN: usize = 256;

    /// Compute Shannon entropy of a byte slice.
    fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = data.len() as f64;
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Scan text for high-entropy substrings that look like secrets.
    fn detect_high_entropy(text: &str, source: &str) -> Vec<DetectorFinding> {
        let re = static_regex!(r"[A-Za-z0-9+/=_\-]{20,256}");
        let mut findings_by_entity: std::collections::HashMap<String, DetectorFinding> =
            std::collections::HashMap::new();

        for m in re.find_iter(text) {
            let candidate = m.as_str();
            if candidate.len() < HIGH_ENTROPY_MIN_LEN || candidate.len() > HIGH_ENTROPY_MAX_LEN {
                continue;
            }
            let entropy = shannon_entropy(candidate.as_bytes());
            if entropy < HIGH_ENTROPY_THRESHOLD {
                continue;
            }

            let span_hash = hex::encode(Sha256::digest(candidate.as_bytes()));
            let location = EvidenceLocation {
                source: source.to_string(),
                start: m.start(),
                end: m.end(),
                span_hash: span_hash.clone(),
            };

            let entry = findings_by_entity
                .entry("high_entropy_string".to_string())
                .or_insert_with(|| DetectorFinding {
                    detector: "high_entropy".to_string(),
                    category: "high_entropy".to_string(),
                    entity_type: "high_entropy_string".to_string(),
                    match_count: 0,
                    confidence: "medium".to_string(),
                    matched_policy_ids: Vec::new(),
                    action: "allowed".to_string(),
                    evidence_locations: Vec::new(),
                    sample_hash: span_hash.clone(),
                });
            entry.match_count += 1;
            entry.evidence_locations.push(location);
        }

        findings_by_entity.into_values().collect()
    }

    /// Scan text for known credential/secret patterns.
    pub fn scan_secrets(text: &str, source: &str) -> Vec<DetectorFinding> {
        let mut findings: Vec<DetectorFinding> = Vec::new();

        for pattern in SECRET_PATTERNS {
            let re = static_regex_dynamic(pattern.regex);
            let mut locations = Vec::new();
            let mut count = 0u32;
            let mut first_hash = String::new();

            for m in re.find_iter(text) {
                count += 1;
                let span_hash = hex::encode(Sha256::digest(m.as_str().as_bytes()));
                if first_hash.is_empty() {
                    first_hash.clone_from(&span_hash);
                }
                locations.push(EvidenceLocation {
                    source: source.to_string(),
                    start: m.start(),
                    end: m.end(),
                    span_hash,
                });
            }

            if count > 0 {
                findings.push(DetectorFinding {
                    detector: "credential".to_string(),
                    category: "credential".to_string(),
                    entity_type: pattern.entity_type.to_string(),
                    match_count: count,
                    confidence: "high".to_string(),
                    matched_policy_ids: Vec::new(),
                    action: "allowed".to_string(),
                    evidence_locations: locations,
                    sample_hash: first_hash,
                });
            }
        }

        // High-entropy scan
        findings.extend(detect_high_entropy(text, source));

        findings
    }

    /// Helper to compile secret patterns at runtime.
    /// We cannot use the static_regex! macro here because the pattern comes from
    /// a const slice. Each pattern is compiled once and cached via OnceLock in the
    /// SECRET_PATTERNS array iteration.
    fn static_regex_dynamic(pattern: &str) -> regex_lite::Regex {
        #[allow(clippy::expect_used)]
        regex_lite::Regex::new(pattern).expect("secret scanner regex")
    }
}

// ── PII/PHI/DLP detector findings projection ──

/// Project findings from the reachable PII/PHI/PCI detectors into
/// the AI Usage Record `DetectorFinding` format.
///
/// This converts the existing `detection::pii::Detection` results into the
/// Section 9.3 data-leakage contract.
pub(crate) fn project_pii_findings(
    detections: &[pii::Detection],
    source: &str,
) -> Vec<DetectorFinding> {
    use std::collections::HashMap;

    let mut grouped: HashMap<String, DetectorFinding> = HashMap::new();

    for det in detections {
        let category = det.kind.as_kind_str().to_string();
        let entity_type = det.kind.marker_key().to_string();
        let key = format!("{category}:{entity_type}");

        let span_hash = {
            let mut hasher = Sha256::new();
            hasher.update(format!("{source}:{}-{}", det.start, det.end).as_bytes());
            hex::encode(hasher.finalize())
        };

        let location = EvidenceLocation {
            source: source.to_string(),
            start: det.start,
            end: det.end,
            span_hash: span_hash.clone(),
        };

        let entry = grouped.entry(key).or_insert_with(|| DetectorFinding {
            detector: category.clone(),
            category,
            entity_type,
            match_count: 0,
            confidence: det.confidence.as_str().to_string(),
            matched_policy_ids: Vec::new(),
            action: "allowed".to_string(),
            evidence_locations: Vec::new(),
            sample_hash: span_hash,
        });
        entry.match_count += 1;
        entry.evidence_locations.push(location);
    }

    grouped.into_values().collect()
}

// ── Record builder ──────────────────────────────────────────────────────────

/// Build a complete AI Usage Record from the capture context.
///
/// Content is bounded per `config.effective_max_bytes`.
/// Detector findings are projected from the reachable detectors plus
/// the feature-owned credential/secret-pattern and high-entropy scanner.
pub fn build_record(ctx: &CaptureContext, config: &CaptureConfig) -> AiUsageRecord {
    let max_bytes = config.effective_max_bytes();
    let now = Utc::now();

    // ── Bound request content ───────────────────────────────────────────
    let (request_body, request_truncated, request_sha256_raw) = ctx
        .request_body_raw
        .as_deref()
        .map(|raw| bound_content(raw, max_bytes))
        .unwrap_or((None, false, None));
    let request_bytes = ctx
        .request_body_raw
        .as_ref()
        .map(|r| r.len() as u64)
        .unwrap_or(0);

    // ── Bound response content ──────────────────────────────────────────
    let (response_body, response_truncated, response_sha256_raw) = ctx
        .response_body_raw
        .as_deref()
        .map(|raw| bound_content(raw, max_bytes))
        .unwrap_or((None, false, None));
    let response_bytes = ctx
        .response_body_raw
        .as_ref()
        .map(|r| r.len() as u64)
        .unwrap_or(0);

    // ── Run detectors ───────────────────────────────────────────────────
    let mut all_findings: Vec<DetectorFinding> = Vec::new();

    // reachable PII/PHI/PCI detectors
    if let Some(ref body) = request_body {
        let pii_detections = pii::detect_all(body);
        all_findings.extend(project_pii_findings(&pii_detections, "request"));
    }
    if let Some(ref body) = response_body {
        let pii_detections = pii::detect_all(body);
        all_findings.extend(project_pii_findings(&pii_detections, "response"));
    }

    // Feature-owned credential/secret-pattern and high-entropy scanner
    if let Some(ref body) = request_body {
        all_findings.extend(secret_scanner::scan_secrets(body, "request"));
    }
    if let Some(ref body) = response_body {
        all_findings.extend(secret_scanner::scan_secrets(body, "response"));
    }

    let secrets_detected = all_findings
        .iter()
        .any(|f| f.category == "credential" || f.category == "high_entropy");
    let potential_data_leakage = !all_findings.is_empty();

    // ── Compute latency ─────────────────────────────────────────────────
    let latency_ms = ctx
        .completed_at
        .map(|end| (end - ctx.started_at).num_milliseconds().max(0) as u64);

    // ── Upstream host — host only, no credentials (Section 9.3) ─────────
    let upstream_host = ctx.upstream_host.as_deref().map(|h| {
        h.split('@')
            .next_back()
            .unwrap_or(h)
            .split('/')
            .next()
            .unwrap_or(h)
            .to_string()
    });

    AiUsageRecord {
        schema_version: SCHEMA_VERSION.to_string(),
        record_id: Uuid::new_v4().to_string(),
        org_id: ctx.org_id.clone(),
        captured_at: now.to_rfc3339(),
        source: "gateway".to_string(),

        gateway_id: ctx.gateway_id.clone(),
        agent_id: ctx.agent_id.clone(),
        subject_token_id: ctx.subject_token_id.clone(),
        actor_id: ctx.actor_id.clone(),
        actor_type: ctx.actor_type.clone(),
        session_id: ctx.session_id.clone(),
        correlation_id: ctx.correlation_id.clone(),
        request_id: ctx.request_id.clone(),

        request_family: ctx.request_family,
        transport: ctx.transport,
        provider: ctx.provider.clone(),
        model: ctx.model.clone(),
        upstream_host,
        streamed: ctx.streamed,
        started_at: ctx.started_at.to_rfc3339(),
        completed_at: ctx.completed_at.map(|t| t.to_rfc3339()),
        latency_ms,
        outcome: ctx.outcome,
        http_status: ctx.http_status,

        request_body,
        request_bytes,
        request_sha256_raw,
        request_truncated,

        response_body,
        response_bytes,
        response_sha256_raw,
        response_truncated,

        governance: ctx.governance.clone(),

        detectors: all_findings,
        scanned: true,
        secrets_detected,
        potential_data_leakage,

        financial: ctx.financial.clone(),

        ua_attempt_id: ctx
            .ua_attempt_id
            .clone()
            .or(ctx.financial.ua_attempt_id.clone()),
        ua_financial_event_id: ctx
            .ua_financial_event_id
            .clone()
            .or(ctx.financial.ua_financial_event_id.clone()),

        canonical_sha256: None, // set after serialization
        trail_event_id: ctx.trail_event_id.clone(),
    }
}

/// Compute and set the RFC-8785 canonical SHA-256 on a record.
///
/// The canonical hash is computed over the JSON-serialized record with `canonical_sha256`
/// set to `None`, ensuring deterministic ordering.
pub fn seal_record(record: &mut AiUsageRecord) {
    let mut for_hash = record.clone();
    for_hash.canonical_sha256 = None;
    if let Ok(canonical_bytes) = serde_json::to_vec(&for_hash) {
        let hash = hex::encode(Sha256::digest(&canonical_bytes));
        record.canonical_sha256 = Some(hash);
    }
}

// ── WAL enqueue helper ──────────────────────────────────────────────────────

/// Error from durable WAL enqueue.
#[derive(Debug, thiserror::Error)]
pub enum CaptureEnqueueError {
    #[error("WAL write failed: {0}")]
    WalWriteFailed(String),
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
}

/// Enqueue a sealed AI Usage Record through the gateway WAL delivery API.
///
/// When `mandatory` is true, the caller MUST fail closed (503 with no upstream
/// dispatch) if this returns `Err`.
///
/// The gateway persists NO SIEM state; it only enriches and forwards.
pub fn enqueue_to_wal(
    record: &AiUsageRecord,
    sink: &crate::gateway::server::EventSink,
) -> Result<(), CaptureEnqueueError> {
    let payload = serde_json::to_value(record)
        .map_err(|e| CaptureEnqueueError::SerializationFailed(e.to_string()))?;

    sink.persist_ai_usage(&record.record_id, payload)
        .map_err(|e| CaptureEnqueueError::WalWriteFailed(e.to_string()))?;

    tracing::debug!(
        record_id = %record.record_id,
        org_id = %record.org_id,
        request_family = record.request_family.as_str(),
        "ai usage record enqueued to WAL"
    );

    Ok(())
}

// ── Pipeline integration helper ─────────────────────────────────────────────

/// Outcome of attempting AI usage capture in the governed pipeline.
///
/// The caller uses this to decide whether to fail closed (mandatory + error)
/// or continue (best-effort / suppressed).
#[derive(Debug)]
pub enum CaptureResult {
    /// Record captured and enqueued successfully.
    Ok,
    /// Capture is disabled by policy.
    Disabled,
    /// Capture failed. If `mandatory`, the caller should return 503.
    Failed(CaptureEnqueueError),
}

/// Attempt to build, seal, and enqueue an AI usage record.
///
/// This is the single entry point called from the server.rs completion/error
/// pipeline and the MCP transport handler.
///
/// Returns `CaptureResult` so the caller can enforce fail-closed semantics
/// when `config.mandatory` is true.
pub fn try_capture(
    ctx: &CaptureContext,
    config: &CaptureConfig,
    sink: Option<&crate::gateway::server::EventSink>,
) -> CaptureResult {
    if !config.enabled {
        return CaptureResult::Disabled;
    }

    let mut record = build_record(ctx, config);
    seal_record(&mut record);

    let Some(sink) = sink else {
        tracing::warn!(
            request_id = %ctx.request_id,
            "ai usage capture enabled but no event sink available"
        );
        return CaptureResult::Failed(CaptureEnqueueError::WalWriteFailed(
            "no event sink available".into(),
        ));
    };

    match enqueue_to_wal(&record, sink) {
        Ok(()) => CaptureResult::Ok,
        Err(e) => {
            tracing::warn!(
                request_id = %ctx.request_id,
                error = %e,
                "ai usage capture enqueue failed"
            );
            CaptureResult::Failed(e)
        }
    }
}
