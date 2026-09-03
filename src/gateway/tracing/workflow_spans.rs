// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Workflow-lineage span emission for the gateway runtime (Phase 5).
//!
//! Each public function emits one structured [`tracing`] span tagged with
//! OTEL-compatible attributes. These spans are captured by the
//! [`tracing-opentelemetry`] layer already configured in `cli/src/telemetry.rs`
//! and exported through the OTEL pipeline to the control plane.
//!
//! **Privacy guarantee**: message content is never included in span attributes.
//! Only structural metadata (model, provider, span_kind, verdict, token counts,
//! duration, cache outcome) is recorded.
//!
//! **Span kinds** (matches `workflow_trace_lineage.span_kind` CHECK constraint):
//!   - `request` — outbound LLM provider request
//!   - `tool_call` — tool/function invocation
//!   - `cache_action` — cache lookup or write
//!   - `approval` — approval request or decision
//!   - `routing_decision` — provider selection outcome

#[cfg(feature = "otlp")]
use opentelemetry::trace::TraceContextExt;
#[cfg(feature = "otlp")]
use opentelemetry::KeyValue;
#[cfg(feature = "otlp")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

// ── Workflow lineage context ──────────────────────────────────────────────────

/// Carries the workflow lineage identifiers for a single gateway request.
///
/// Extracted from incoming request headers and threaded through the request
/// lifecycle so that each emitted span carries consistent lineage context.
#[derive(Clone, Debug, Default)]
pub struct WorkflowLineageContext {
    /// Logical workflow identifier from `X-Workflow-Id`.
    pub workflow_id: Option<String>,
    /// Parent lineage context from `X-Lineage-Id`.
    pub lineage_id: Option<String>,
    /// W3C traceparent (already normalised by `request_id::normalize_or_generate_traceparent`).
    pub traceparent: String,
    /// Request correlation ID.
    pub request_id: String,
    /// Gateway identifier, if known.
    pub gateway_id: Option<String>,
}

impl WorkflowLineageContext {
    /// Returns `true` when the request carries a workflow context.
    pub fn has_workflow_context(&self) -> bool {
        self.workflow_id
            .as_deref()
            .and_then(non_empty_trimmed)
            .is_some()
    }

    /// Extracts the W3C trace-id segment from `self.traceparent`.
    ///
    /// Returns `None` when the traceparent is malformed.
    pub fn trace_id(&self) -> Option<&str> {
        parse_traceparent(&self.traceparent).map(|(_, trace_id, _, _)| trace_id)
    }
}

fn non_empty_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn parse_traceparent(traceparent: &str) -> Option<(&str, &str, &str, &str)> {
    let mut parts = traceparent.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let parent_id = parts.next()?;
    let trace_flags = parts.next()?;

    if parts.next().is_some() {
        return None;
    }

    if !is_hex_segment(version, 2) || version.eq_ignore_ascii_case("ff") {
        return None;
    }
    if !is_hex_segment(trace_id, 32) || trace_id.bytes().all(|byte| byte == b'0') {
        return None;
    }
    if !is_hex_segment(parent_id, 16) || parent_id.bytes().all(|byte| byte == b'0') {
        return None;
    }
    if !is_hex_segment(trace_flags, 2) {
        return None;
    }

    Some((version, trace_id, parent_id, trace_flags))
}

fn is_hex_segment(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// ── Internal annotation helper ────────────────────────────────────────────────

/// Sets the common workflow-lineage OTEL attributes on an existing span.
///
/// Always called inside a `tracing::info_span!` entry to ensure the span has
/// already been registered with the subscriber before attributes are set.
fn annotate_lineage_attributes(span: &tracing::Span, ctx: &WorkflowLineageContext) {
    #[cfg(feature = "otlp")]
    {
        let context = span.context();
        let otel_span = context.span();

        otel_span.set_attribute(KeyValue::new(
            "verdictan.request_id",
            ctx.request_id.clone(),
        ));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.traceparent",
            ctx.traceparent.clone(),
        ));
        if let Some(wf_id) = ctx.workflow_id.as_deref().and_then(non_empty_trimmed) {
            otel_span.set_attribute(KeyValue::new("verdictan.workflow.id", wf_id.to_string()));
        }
        if let Some(ln_id) = ctx.lineage_id.as_deref().and_then(non_empty_trimmed) {
            otel_span.set_attribute(KeyValue::new("verdictan.lineage.id", ln_id.to_string()));
        }
        if let Some(gw_id) = ctx.gateway_id.as_deref().and_then(non_empty_trimmed) {
            otel_span.set_attribute(KeyValue::new("verdictan.gateway.id", gw_id.to_string()));
        }
    }
    #[cfg(not(feature = "otlp"))]
    {
        let _ = (span, ctx);
    }
}

// ── Public span emitters ──────────────────────────────────────────────────────

/// Parameters for an outbound LLM provider request span.
#[derive(Debug, Default)]
pub(crate) struct RequestSpanParams<'a> {
    /// Resolved provider identifier (e.g. `"openai"`, `"anthropic"`).
    pub provider: Option<&'a str>,
    /// Model identifier as resolved by routing (not the raw client request).
    pub model: Option<&'a str>,
    /// HTTP path of the upstream endpoint (e.g. `"/v1/chat/completions"`).
    pub path: Option<&'a str>,
    /// Enforcement verdict for this request (after input policy evaluation).
    pub verdict: Option<&'a str>,
    /// Reason code from the enforcement engine.
    pub reason_code: Option<&'a str>,
    /// End-to-end request duration in milliseconds.
    pub duration_ms: Option<i64>,
    /// HTTP status code from the upstream provider.
    pub upstream_status: Option<u16>,
}

/// Emit a `request` lineage span covering one outbound LLM provider request.
///
/// This span is emitted regardless of whether the request has a workflow
/// context to ensure consistent span coverage across all gateway requests.
/// The span's `verdictan.workflow.id` attribute is set only when available.
pub(crate) fn emit_request_span(ctx: &WorkflowLineageContext, params: &RequestSpanParams<'_>) {
    let span = tracing::info_span!(
        "verdictan.workflow.request",
        verdictan.span.kind = "request",
        verdictan.request_id = %ctx.request_id,
        verdictan.workflow.id = tracing::field::Empty,
        verdictan.lineage.id = tracing::field::Empty,
        gen_ai.system = tracing::field::Empty,
        gen_ai.request.model = tracing::field::Empty,
        url.path = tracing::field::Empty,
        verdictan.policy.verdict = tracing::field::Empty,
        verdictan.policy.reason_code = tracing::field::Empty,
        verdictan.duration_ms = tracing::field::Empty,
        http.response.status_code = tracing::field::Empty,
    );

    crate::telemetry::attach_parent_trace_context(&span, &ctx.traceparent);

    {
        let _guard = span.enter();

        if let Some(workflow_id) = ctx.workflow_id.as_deref().and_then(non_empty_trimmed) {
            span.record(
                "verdictan.workflow.id",
                tracing::field::display(workflow_id),
            );
        }
        if let Some(lineage_id) = ctx.lineage_id.as_deref().and_then(non_empty_trimmed) {
            span.record("verdictan.lineage.id", tracing::field::display(lineage_id));
        }
        if let Some(provider) = params.provider {
            span.record("gen_ai.system", tracing::field::display(provider));
        }
        if let Some(model) = params.model {
            span.record("gen_ai.request.model", tracing::field::display(model));
        }
        if let Some(path) = params.path {
            span.record("url.path", tracing::field::display(path));
        }
        if let Some(verdict) = params.verdict {
            span.record("verdictan.policy.verdict", tracing::field::display(verdict));
        }
        if let Some(rc) = params.reason_code {
            span.record("verdictan.policy.reason_code", tracing::field::display(rc));
        }
        if let Some(ms) = params.duration_ms {
            span.record("verdictan.duration_ms", ms);
        }
        if let Some(status) = params.upstream_status {
            span.record("http.response.status_code", status as i64);
        }

        #[cfg(feature = "otlp")]
        {
            let context = span.context();
            let otel_span = context.span();
            annotate_lineage_attributes(&span, ctx);
            otel_span.set_attribute(KeyValue::new("verdictan.span.kind", "request"));
            if let Some(provider) = params.provider {
                otel_span.set_attribute(KeyValue::new("gen_ai.system", provider.to_string()));
            }
            if let Some(model) = params.model {
                otel_span.set_attribute(KeyValue::new("gen_ai.request.model", model.to_string()));
            }
            if let Some(path) = params.path {
                otel_span.set_attribute(KeyValue::new("url.path", path.to_string()));
            }
            if let Some(verdict) = params.verdict {
                otel_span.set_attribute(KeyValue::new(
                    "verdictan.policy.verdict",
                    verdict.to_string(),
                ));
            }
            if let Some(rc) = params.reason_code {
                otel_span.set_attribute(KeyValue::new(
                    "verdictan.policy.reason_code",
                    rc.to_string(),
                ));
            }
            if let Some(ms) = params.duration_ms {
                otel_span.set_attribute(KeyValue::new("verdictan.duration_ms", ms));
            }
            if let Some(status) = params.upstream_status {
                otel_span.set_attribute(KeyValue::new("http.response.status_code", status as i64));
            }
        }
        #[cfg(not(feature = "otlp"))]
        annotate_lineage_attributes(&span, ctx);
    }
}

/// Outcome of a cache operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheOutcome {
    Hit,
    Miss,
    Put,
}

impl CacheOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Put => "put",
        }
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
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Record};
    use tracing::Subscriber;
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::registry::LookupSpan;

    use super::{emit_request_span, RequestSpanParams, WorkflowLineageContext};

    #[derive(Clone, Default)]
    struct SpanCaptureLayer {
        fields: Arc<Mutex<BTreeMap<String, String>>>,
    }

    impl SpanCaptureLayer {
        fn snapshot(&self) -> BTreeMap<String, String> {
            match self.fields.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        fn insert_fields(&self, span_name: Option<&str>, values: BTreeMap<String, String>) {
            let mut guard = match self.fields.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(span_name) = span_name {
                guard.insert("span.name".to_string(), span_name.to_string());
            }
            guard.extend(values);
        }
    }

    impl<S> Layer<S> for SpanCaptureLayer
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_new_span(&self, attrs: &Attributes<'_>, id: &tracing::Id, ctx: Context<'_, S>) {
            let mut values = BTreeMap::new();
            attrs.record(&mut FieldCaptureVisitor::new(&mut values));
            self.insert_fields(ctx.span(id).map(|span| span.metadata().name()), values);
        }

        fn on_record(&self, id: &tracing::Id, record: &Record<'_>, ctx: Context<'_, S>) {
            let mut values = BTreeMap::new();
            record.record(&mut FieldCaptureVisitor::new(&mut values));
            self.insert_fields(ctx.span(id).map(|span| span.metadata().name()), values);
        }
    }

    struct FieldCaptureVisitor<'a> {
        values: &'a mut BTreeMap<String, String>,
    }

    impl<'a> FieldCaptureVisitor<'a> {
        fn new(values: &'a mut BTreeMap<String, String>) -> Self {
            Self { values }
        }
    }

    impl Visit for FieldCaptureVisitor<'_> {
        fn record_i64(&mut self, field: &Field, value: i64) {
            self.values
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.values
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_bool(&mut self, field: &Field, value: bool) {
            self.values
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.values
                .insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.values
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    fn test_ctx() -> WorkflowLineageContext {
        WorkflowLineageContext {
            workflow_id: Some("  wf-123  ".to_string()),
            lineage_id: Some("  ln-456  ".to_string()),
            traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
            request_id: "req-123".to_string(),
            gateway_id: Some(" gw-test ".to_string()),
        }
    }

    #[test]
    fn parse_traceparent_valid() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let result = super::parse_traceparent(tp);
        assert!(result.is_some());
        let (version, trace_id, parent_id, flags) = result.unwrap();
        assert_eq!(version, "00");
        assert_eq!(trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(parent_id, "00f067aa0ba902b7");
        assert_eq!(flags, "01");
    }

    #[test]
    fn parse_traceparent_invalid_version_ff() {
        let tp = "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert!(super::parse_traceparent(tp).is_none());
    }

    #[test]
    fn parse_traceparent_invalid_all_zero_trace_id() {
        let tp = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        assert!(super::parse_traceparent(tp).is_none());
    }

    #[test]
    fn parse_traceparent_invalid_all_zero_parent_id() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01";
        assert!(super::parse_traceparent(tp).is_none());
    }

    #[test]
    fn parse_traceparent_too_many_segments() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra";
        assert!(super::parse_traceparent(tp).is_none());
    }

    #[test]
    fn parse_traceparent_wrong_length_version() {
        let tp = "000-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert!(super::parse_traceparent(tp).is_none());
    }

    #[test]
    fn parse_traceparent_non_hex_characters() {
        let tp = "00-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ-00f067aa0ba902b7-01";
        assert!(super::parse_traceparent(tp).is_none());
    }

    #[test]
    fn parse_traceparent_too_few_segments() {
        assert!(super::parse_traceparent("00-abc").is_none());
        assert!(super::parse_traceparent("").is_none());
    }

    #[test]
    fn is_hex_segment_valid() {
        assert!(super::is_hex_segment("0123456789abcdef", 16));
        assert!(super::is_hex_segment("ABCDEF", 6));
    }

    #[test]
    fn is_hex_segment_wrong_length() {
        assert!(!super::is_hex_segment("abcde", 6));
        assert!(!super::is_hex_segment("abcdefg", 6));
    }

    #[test]
    fn is_hex_segment_non_hex() {
        assert!(!super::is_hex_segment("xyz123", 6));
    }

    #[test]
    fn workflow_lineage_has_workflow_context_present() {
        let ctx = WorkflowLineageContext {
            workflow_id: Some("wf-1".to_string()),
            ..Default::default()
        };
        assert!(ctx.has_workflow_context());
    }

    #[test]
    fn workflow_lineage_has_workflow_context_empty_string() {
        let ctx = WorkflowLineageContext {
            workflow_id: Some("   ".to_string()),
            ..Default::default()
        };
        assert!(!ctx.has_workflow_context());
    }

    #[test]
    fn workflow_lineage_has_workflow_context_none() {
        let ctx = WorkflowLineageContext {
            workflow_id: None,
            ..Default::default()
        };
        assert!(!ctx.has_workflow_context());
    }

    #[test]
    fn workflow_lineage_trace_id_valid() {
        let ctx = WorkflowLineageContext {
            traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
            ..Default::default()
        };
        assert_eq!(ctx.trace_id(), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
    }

    #[test]
    fn workflow_lineage_trace_id_malformed() {
        let ctx = WorkflowLineageContext {
            traceparent: "not-a-valid-traceparent".to_string(),
            ..Default::default()
        };
        assert_eq!(ctx.trace_id(), None);
    }

    #[test]
    fn cache_outcome_as_str() {
        assert_eq!(super::CacheOutcome::Hit.as_str(), "hit");
        assert_eq!(super::CacheOutcome::Miss.as_str(), "miss");
        assert_eq!(super::CacheOutcome::Put.as_str(), "put");
    }

    #[test]
    fn non_empty_trimmed_whitespace_only() {
        assert_eq!(super::non_empty_trimmed(""), None);
        assert_eq!(super::non_empty_trimmed("  "), None);
        assert_eq!(super::non_empty_trimmed("\t\n"), None);
    }

    #[test]
    fn non_empty_trimmed_with_content() {
        assert_eq!(super::non_empty_trimmed("  hello  "), Some("hello"));
        assert_eq!(super::non_empty_trimmed("x"), Some("x"));
    }

    #[test]
    fn emit_request_span_records_trimmed_lineage_fields() {
        let ctx = test_ctx();
        let params = RequestSpanParams {
            provider: Some("openai"),
            model: Some("gpt-4o-mini"),
            path: Some("/v1/chat/completions"),
            verdict: Some("allow"),
            reason_code: Some("policy-ok"),
            duration_ms: Some(42),
            upstream_status: Some(200),
        };
        let layer = SpanCaptureLayer::default();
        let subscriber = tracing_subscriber::registry().with(layer.clone());

        tracing::subscriber::with_default(subscriber, || emit_request_span(&ctx, &params));

        let captured = layer.snapshot();
        assert_eq!(
            captured.get("span.name").map(String::as_str),
            Some("verdictan.workflow.request")
        );
        assert_eq!(
            captured.get("verdictan.request_id").map(String::as_str),
            Some("req-123")
        );
        assert_eq!(
            captured.get("verdictan.workflow.id").map(String::as_str),
            Some("wf-123")
        );
        assert_eq!(
            captured.get("verdictan.lineage.id").map(String::as_str),
            Some("ln-456")
        );
        assert_eq!(
            captured.get("gen_ai.system").map(String::as_str),
            Some("openai")
        );
        assert_eq!(
            captured.get("gen_ai.request.model").map(String::as_str),
            Some("gpt-4o-mini")
        );
        assert_eq!(
            captured.get("url.path").map(String::as_str),
            Some("/v1/chat/completions")
        );
        assert_eq!(
            captured.get("verdictan.duration_ms").map(String::as_str),
            Some("42")
        );
        assert_eq!(
            captured
                .get("http.response.status_code")
                .map(String::as_str),
            Some("200")
        );
    }
}
