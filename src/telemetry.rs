// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::sync::OnceLock;

use bytes::Bytes;
use http::StatusCode;

use crate::error::CliError;

static TELEMETRY_INIT: OnceLock<Result<(), String>> = OnceLock::new();

#[cfg(feature = "otlp")]
fn deployment_environment() -> Result<String, anyhow::Error> {
    std::env::var("VERDICTAN_ENV")
        .map_err(|_| anyhow::anyhow!("VERDICTAN_ENV must be set for CLI telemetry"))
}

struct ServiceJsonWriter<W> {
    inner: W,
    service_prefix_written: bool,
}

impl<W: std::io::Write> std::io::Write for ServiceJsonWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.service_prefix_written && buf.first() == Some(&b'{') {
            self.service_prefix_written = true;
            self.inner.write_all(b"{\"service\":\"verdictan-cli\",")?;
            self.inner.write_all(&buf[1..])?;
            Ok(buf.len())
        } else {
            self.inner.write(buf)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct ServiceMakeWriter;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ServiceMakeWriter {
    type Writer = ServiceJsonWriter<std::io::Stdout>;

    fn make_writer(&'a self) -> Self::Writer {
        ServiceJsonWriter {
            inner: std::io::stdout(),
            service_prefix_written: false,
        }
    }
}

#[cfg(feature = "otlp")]
pub enum ResolvedOtlpConfig {
    ExplicitGrpc { endpoint: String },
}

#[cfg(feature = "otlp")]
impl ResolvedOtlpConfig {
    fn endpoint(&self) -> Option<&str> {
        match self {
            Self::ExplicitGrpc { endpoint } => Some(endpoint.as_str()),
        }
    }
}

pub(crate) fn init(enable_otlp: bool) -> Result<(), CliError> {
    init_once(&TELEMETRY_INIT, || init_inner(enable_otlp))
}

/// Lightweight telemetry for simple commands that only need stderr logging.
///
/// Skips OpenTelemetry propagator setup, OTLP exporter resolution, and
/// JSON-format branching. Installs a plain stderr `fmt` subscriber with an
/// env-filter so that `RUST_LOG` / `VERDICTAN_LOG` still work.
pub(crate) fn init_minimal() -> Result<(), CliError> {
    init_once(&TELEMETRY_INIT, || {
        use tracing_subscriber::util::SubscriberInitExt;

        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .finish()
            .try_init()
            .map_err(|err| err.to_string())
    })
}

/// Detect whether JSON structured logging is requested via `VERDICTAN_LOG_FORMAT=json`.
/// All other values (including unset) produce human-readable text output.
fn resolve_json_log_format(value: Option<&str>) -> bool {
    value
        .map(|raw| raw.trim().eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}

fn use_json_log_format() -> bool {
    resolve_json_log_format(std::env::var("VERDICTAN_LOG_FORMAT").ok().as_deref())
}

fn init_once<E>(
    state: &OnceLock<Result<(), String>>,
    initializer: impl FnOnce() -> Result<(), E>,
) -> Result<(), CliError>
where
    E: ToString,
{
    match state.get_or_init(|| initializer().map_err(|err| err.to_string())) {
        Ok(()) => Ok(()),
        Err(message) => Err(CliError::internal(message.clone())),
    }
}

fn init_inner(enable_otlp: bool) -> Result<(), anyhow::Error> {
    if use_json_log_format() {
        init_inner_with_format(enable_otlp, true)
    } else {
        init_inner_with_format(enable_otlp, false)
    }
}

/// Shared subscriber initialization.
///
/// `use_json = true` → JSON structured output (suitable for log aggregators).
/// Emits `timestamp`, `level`, `fields.message`, `target`,
/// and a static `service` field per ADR-019.
/// Set `VERDICTAN_LOG_FORMAT=json` to enable.
/// `use_json = false` → Human-readable text output (default).
fn init_inner_with_format(enable_otlp: bool, use_json: bool) -> Result<(), anyhow::Error> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    #[cfg(feature = "otlp")]
    {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
    }

    #[cfg(feature = "otlp")]
    if enable_otlp {
        if let Some(config) = resolve_otlp_config() {
            use opentelemetry::trace::TracerProvider as _;
            use opentelemetry::KeyValue;
            use opentelemetry_otlp::WithExportConfig;
            use opentelemetry_sdk::trace::SdkTracerProvider;
            use opentelemetry_sdk::Resource;

            let deployment_environment = deployment_environment()?;

            let resource = Resource::builder()
                .with_service_name("verdictan-cli")
                .with_attributes([
                    KeyValue::new("service.component", "proxy"),
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    KeyValue::new("deployment.environment", deployment_environment),
                ])
                .build();

            let provider = match config {
                ResolvedOtlpConfig::ExplicitGrpc { endpoint } => {
                    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
                        .with_tonic()
                        .with_endpoint(endpoint)
                        .build()
                        .map_err(|err| {
                            anyhow::anyhow!("failed to build OTLP span exporter: {err}")
                        })?;

                    SdkTracerProvider::builder()
                        .with_resource(resource)
                        .with_batch_exporter(span_exporter)
                        .build()
                }
            };

            let tracer = provider.tracer("verdictan-cli");
            opentelemetry::global::set_tracer_provider(provider);

            let json_fmt = use_json.then(|| {
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(ServiceMakeWriter)
                    .with_current_span(false)
                    .with_span_list(false)
            });
            let text_fmt = (!use_json).then(|| {
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_target(true)
                    .with_thread_ids(false)
                    .with_file(false)
                    .with_line_number(false)
            });

            tracing_subscriber::registry()
                .with(filter)
                .with(json_fmt)
                .with(text_fmt)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .try_init()?;
            return Ok(());
        }
    }

    #[cfg(not(feature = "otlp"))]
    let _ = enable_otlp;

    let json_fmt = use_json.then(|| {
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(ServiceMakeWriter)
            .with_current_span(false)
            .with_span_list(false)
    });
    let text_fmt = (!use_json).then(|| {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(json_fmt)
        .with(text_fmt)
        .try_init()?;
    Ok(())
}

pub(crate) fn attach_parent_trace_context(span: &tracing::Span, traceparent: &str) {
    #[cfg(feature = "otlp")]
    {
        use opentelemetry::propagation::Extractor;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        struct TraceparentCarrier<'a> {
            traceparent: &'a str,
        }

        impl Extractor for TraceparentCarrier<'_> {
            fn get(&self, key: &str) -> Option<&str> {
                if key.eq_ignore_ascii_case("traceparent") {
                    Some(self.traceparent)
                } else {
                    None
                }
            }

            fn keys(&self) -> Vec<&str> {
                vec!["traceparent"]
            }
        }

        let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&TraceparentCarrier { traceparent })
        });
        let _ = span.set_parent(parent_context);
    }
    #[cfg(not(feature = "otlp"))]
    {
        let _ = (span, traceparent);
    }
}

pub(crate) fn annotate_workflow_phase_span(
    span: &tracing::Span,
    workflow_name: &str,
    workflow_phase: &str,
) {
    #[cfg(feature = "otlp")]
    {
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry::KeyValue;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let context = span.context();
        let otel_span = context.span();

        otel_span.set_attribute(KeyValue::new(
            "verdictan.span.kind",
            "workflow_phase".to_string(),
        ));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.workflow.name",
            workflow_name.to_string(),
        ));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.workflow.phase",
            workflow_phase.to_string(),
        ));
    }
    #[cfg(not(feature = "otlp"))]
    {
        let _ = (span, workflow_name, workflow_phase);
    }
}

pub(crate) fn with_policy_span<T>(
    policy_kind: &str,
    policy_phase: &str,
    f: impl FnOnce(&tracing::Span) -> T,
) -> T {
    let span = tracing::info_span!(
        "verdictan_policy_evaluation",
        verdictan_policy_kind = %policy_kind,
        verdictan_policy_phase = %policy_phase,
        verdictan_policy_verdict = tracing::field::Empty,
        verdictan_policy_reason_code = tracing::field::Empty
    );
    let _guard = span.enter();
    f(&span)
}

pub(crate) fn annotate_policy_result_span(
    span: &tracing::Span,
    policy_result: &crate::gateway::enforcement::PolicyResult,
) {
    #[cfg(not(feature = "otlp"))]
    {
        let _ = (span, policy_result);
    }
    #[cfg(feature = "otlp")]
    {
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry::{Array, KeyValue, Value};
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let context = span.context();
        let otel_span = context.span();

        span.record(
            "verdictan_policy_verdict",
            tracing::field::display(policy_result.verdict.to_string()),
        );
        span.record(
            "verdictan_policy_reason_code",
            tracing::field::display(&policy_result.reason_code),
        );

        otel_span.set_attribute(KeyValue::new(
            "verdictan.span.kind",
            "policy_evaluation".to_string(),
        ));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.guardrail.name",
            policy_result.policy_kind.clone(),
        ));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.policy.kind",
            policy_result.policy_kind.clone(),
        ));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.policy.phase",
            policy_result.phase.clone(),
        ));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.policy.verdict",
            policy_result.verdict.to_string(),
        ));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.policy.reason_code",
            policy_result.reason_code.clone(),
        ));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.policy.redaction_target_count",
            policy_result
                .redaction_targets
                .as_ref()
                .map(|targets| targets.len() as i64)
                .unwrap_or(0),
        ));

        if let Some(details) = &policy_result.details {
            if let Some(score) = read_number_path(details, &["metrics", "aggregate"]) {
                otel_span.set_attribute(KeyValue::new("verdictan.policy.aggregate_score", score));
            }
            if let Some(threshold) = read_number_path(details, &["thresholds", "min_aggregate"]) {
                otel_span.set_attribute(KeyValue::new(
                    "verdictan.policy.aggregate_threshold",
                    threshold,
                ));
            }
            if let Some(assertion_count) = details
                .get("assertions")
                .and_then(|value| value.as_array())
                .map(|value| value.len() as i64)
            {
                otel_span.set_attribute(KeyValue::new(
                    "verdictan.policy.assertion_count",
                    assertion_count,
                ));
            }
            if let Some(failure_count) = details
                .get("failures")
                .and_then(|value| value.as_array())
                .map(|value| value.len() as i64)
            {
                otel_span.set_attribute(KeyValue::new(
                    "verdictan.policy.failure_count",
                    failure_count,
                ));
            }
            if let Some(tool_names) = details
                .get("tool_names")
                .and_then(json_string_array)
                .filter(|names| !names.is_empty())
            {
                otel_span.set_attribute(KeyValue::new(
                    "verdictan.tool.names",
                    Value::Array(Array::String(
                        tool_names.iter().cloned().map(Into::into).collect(),
                    )),
                ));
                otel_span.set_attribute(KeyValue::new(
                    "verdictan.tool.count",
                    tool_names.len() as i64,
                ));
            }
        }
    }
}

pub(crate) fn annotate_provider_span(
    span: &tracing::Span,
    request_id: &str,
    provider: &str,
    path: &str,
    upstream_base: &str,
    model: Option<&str>,
) {
    let operation_name = path.trim_start_matches("/v1/").replace('/', ".");

    span.record("gen_ai_system", tracing::field::display(provider));
    span.record(
        "gen_ai_operation_name",
        tracing::field::display(&operation_name),
    );

    if let Ok(url) = reqwest::Url::parse(upstream_base) {
        if let Some(host) = url.host_str() {
            span.record("server_address", tracing::field::display(host));
            #[cfg(feature = "otlp")]
            {
                use opentelemetry::trace::TraceContextExt;
                use opentelemetry::KeyValue;
                use tracing_opentelemetry::OpenTelemetrySpanExt;
                let context = span.context();
                context
                    .span()
                    .set_attribute(KeyValue::new("server.address", host.to_string()));
            }
        }
    }

    if let Some(model) = model {
        span.record("gen_ai_request_model", tracing::field::display(model));
    }

    #[cfg(feature = "otlp")]
    {
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry::KeyValue;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let context = span.context();
        let otel_span = context.span();

        otel_span.set_attribute(KeyValue::new("verdictan.span.type", "llm".to_string()));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.request_id",
            request_id.to_string(),
        ));
        otel_span.set_attribute(KeyValue::new("gen_ai.system", provider.to_string()));
        otel_span.set_attribute(KeyValue::new("gen_ai.operation.name", operation_name));
        otel_span.set_attribute(KeyValue::new("url.path", path.to_string()));
        if let Some(model) = model {
            otel_span.set_attribute(KeyValue::new("gen_ai.request.model", model.to_string()));
        }
    }
    #[cfg(not(feature = "otlp"))]
    {
        let _ = (request_id, upstream_base);
    }
}

/// Annotate a score span with the full judge result metadata.
///
/// The span should carry `verdictan.span.type = "score"` (set separately via
/// `annotate_span_type`). This function records the scorer identity, numeric
/// score, pass threshold, verdict, and rationale for audit.
///
/// SEC-004: only the explicit `rationale` field emitted by the judge is stored.
/// Opaque chain-of-thought tokens not in the final message are never captured.
pub(crate) fn annotate_score_span_attributes(
    span: &tracing::Span,
    judge: &crate::policy::llm_judge::JudgeResult,
    latency_ms: Option<i64>,
) {
    #[cfg(feature = "otlp")]
    {
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry::KeyValue;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let context = span.context();
        let otel_span = context.span();

        otel_span.set_attribute(KeyValue::new("verdictan.span.type", "score".to_string()));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.score.scorer_name",
            judge.scorer_name.clone(),
        ));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.score.scorer_model",
            judge.scorer_model.clone(),
        ));
        otel_span.set_attribute(KeyValue::new("verdictan.score.score", judge.score));
        otel_span.set_attribute(KeyValue::new("verdictan.score.threshold", judge.threshold));
        otel_span.set_attribute(KeyValue::new(
            "verdictan.score.verdict",
            judge.verdict.as_str().to_string(),
        ));
        if let Some(rationale) = &judge.rationale {
            otel_span.set_attribute(KeyValue::new(
                "verdictan.score.rationale",
                rationale.clone(),
            ));
        }
        if let Some(ms) = latency_ms {
            otel_span.set_attribute(KeyValue::new("verdictan.score.latency_ms", ms));
        }
    }
    #[cfg(not(feature = "otlp"))]
    {
        let _ = (span, judge, latency_ms);
    }
}

pub(crate) fn annotate_provider_request_attributes(
    span: &tracing::Span,
    provider: &str,
    path: &str,
    body: &Bytes,
    cache_hit: bool,
    verdictan: Option<&serde_json::Map<String, serde_json::Value>>,
    capture_payloads: bool,
) {
    #[cfg(not(feature = "otlp"))]
    {
        let _ = (
            span,
            provider,
            path,
            body,
            cache_hit,
            verdictan,
            capture_payloads,
        );
    }
    #[cfg(feature = "otlp")]
    {
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry::{Array, KeyValue, Value};
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let context = span.context();
        let otel_span = context.span();
        otel_span.set_attribute(KeyValue::new("verdictan.cache_hit", cache_hit));
        span.record("verdictan_cache_hit", tracing::field::display(cache_hit));
        if capture_payloads {
            let request_body = truncate_utf8_bytes(body, 4096);
            otel_span.set_attribute(KeyValue::new(
                "verdictan.request.body",
                request_body.clone(),
            ));
            span.record(
                "verdictan_request_body",
                tracing::field::display(&request_body),
            );
        }

        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
            return;
        };

        if let Some(object) = value.as_object() {
            let provider_id = build_provider_id(
                provider,
                path,
                object.get("model").and_then(|item| item.as_str()),
            );
            otel_span.set_attribute(KeyValue::new("verdictan.provider.id", provider_id.clone()));
            span.record(
                "verdictan_provider_id",
                tracing::field::display(&provider_id),
            );

            if let Some(value) = json_int(object.get("max_tokens")) {
                otel_span.set_attribute(KeyValue::new("gen_ai.request.max_tokens", value));
                span.record("gen_ai_request_max_tokens", tracing::field::display(value));
            }
            if let Some(value) = json_float(object.get("temperature")) {
                otel_span.set_attribute(KeyValue::new("gen_ai.request.temperature", value));
                span.record("gen_ai_request_temperature", tracing::field::display(value));
            }
            if let Some(value) = json_float(object.get("top_p")) {
                otel_span.set_attribute(KeyValue::new("gen_ai.request.top_p", value));
                span.record("gen_ai_request_top_p", tracing::field::display(value));
            }

            if let Some(stop_sequences) = object.get("stop").and_then(json_string_array) {
                let stop_sequences_json =
                    serde_json::to_string(&stop_sequences).unwrap_or_default();
                otel_span.set_attribute(KeyValue::new(
                    "gen_ai.request.stop_sequences",
                    Value::Array(Array::String(
                        stop_sequences.iter().cloned().map(Into::into).collect(),
                    )),
                ));
                span.record(
                    "gen_ai_request_stop_sequences",
                    tracing::field::display(&stop_sequences_json),
                );
            }

            let requested_tools = extract_requested_tool_names(object);
            if !requested_tools.is_empty() {
                let requested_tools_json =
                    serde_json::to_string(&requested_tools).unwrap_or_default();
                otel_span.set_attribute(KeyValue::new(
                    "verdictan.tool.requested_count",
                    requested_tools.len() as i64,
                ));
                otel_span.set_attribute(KeyValue::new(
                    "verdictan.tool.requested_names",
                    Value::Array(Array::String(
                        requested_tools.iter().cloned().map(Into::into).collect(),
                    )),
                ));
                span.record(
                    "verdictan_tool_requested_count",
                    tracing::field::display(requested_tools.len()),
                );
                span.record(
                    "verdictan_tool_requested_names",
                    tracing::field::display(&requested_tools_json),
                );
            }

            if let Some(verdictan) =
                verdictan.or_else(|| object.get("verdictan").and_then(|item| item.as_object()))
            {
                if let Some(prompt_label) = verdictan
                    .get("prompt")
                    .and_then(|item| item.as_object())
                    .and_then(|item| item.get("label"))
                    .and_then(|item| item.as_str())
                    .or_else(|| verdictan.get("prompt_label").and_then(|item| item.as_str()))
                {
                    otel_span.set_attribute(KeyValue::new(
                        "verdictan.prompt.label",
                        prompt_label.to_string(),
                    ));
                    span.record(
                        "verdictan_prompt_label",
                        tracing::field::display(prompt_label),
                    );
                }

                if let Some(test_index) = verdictan
                    .get("test")
                    .and_then(|item| item.as_object())
                    .and_then(|item| item.get("index"))
                    .and_then(json_int_from_value)
                    .or_else(|| verdictan.get("test_index").and_then(json_int_from_value))
                {
                    otel_span.set_attribute(KeyValue::new("verdictan.test.index", test_index));
                    span.record("verdictan_test_index", tracing::field::display(test_index));
                }

                if let Some(trajectory_steps) = verdictan
                    .get("trajectory")
                    .and_then(|value| value.as_array())
                    .map(|steps| steps.len() as i64)
                {
                    otel_span.set_attribute(KeyValue::new(
                        "verdictan.trajectory.step_count",
                        trajectory_steps,
                    ));
                }

                if verdictan.get("trace").is_some() {
                    otel_span.set_attribute(KeyValue::new("verdictan.trace.hint_present", true));
                }
            }
        }
    }
}

#[cfg(feature = "otlp")]
fn read_number_path(value: &serde_json::Value, path: &[&str]) -> Option<f64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }

    current.as_f64()
}

#[cfg(feature = "otlp")]
fn extract_requested_tool_names(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Vec<String> {
    object
        .get("tools")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    item.get("function")
                        .and_then(|value| value.get("name"))
                        .and_then(|value| value.as_str())
                        .or_else(|| item.get("name").and_then(|value| value.as_str()))
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty())
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(crate) fn annotate_provider_response_attributes(
    span: &tracing::Span,
    status: StatusCode,
    body: &Bytes,
    cache_hit: bool,
    capture_payloads: bool,
) {
    #[cfg(not(feature = "otlp"))]
    {
        let _ = (span, status, body, cache_hit, capture_payloads);
    }
    #[cfg(feature = "otlp")]
    {
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry::{Array, KeyValue, Value};
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let context = span.context();
        let otel_span = context.span();
        otel_span.set_attribute(KeyValue::new(
            "http.response.status_code",
            i64::from(status.as_u16()),
        ));
        otel_span.set_attribute(KeyValue::new("verdictan.cache_hit", cache_hit));
        span.record(
            "http_response_status_code",
            tracing::field::display(status.as_u16()),
        );
        span.record("verdictan_cache_hit", tracing::field::display(cache_hit));
        if capture_payloads {
            let response_body = truncate_utf8_bytes(body, 4096);
            otel_span.set_attribute(KeyValue::new(
                "verdictan.response.body",
                response_body.clone(),
            ));
            span.record(
                "verdictan_response_body",
                tracing::field::display(&response_body),
            );
        }

        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
            return;
        };

        let Some(object) = value.as_object() else {
            return;
        };

        if let Some(usage) = object.get("usage").and_then(|item| item.as_object()) {
            if let Some(value) = usage
                .get("input_tokens")
                .and_then(json_int_from_value)
                .or_else(|| usage.get("prompt_tokens").and_then(json_int_from_value))
            {
                otel_span.set_attribute(KeyValue::new("gen_ai.usage.input_tokens", value));
                span.record("gen_ai_usage_input_tokens", tracing::field::display(value));
            }
            if let Some(value) = usage
                .get("output_tokens")
                .and_then(json_int_from_value)
                .or_else(|| usage.get("completion_tokens").and_then(json_int_from_value))
            {
                otel_span.set_attribute(KeyValue::new("gen_ai.usage.output_tokens", value));
                span.record("gen_ai_usage_output_tokens", tracing::field::display(value));
            }
            if let Some(value) = usage.get("total_tokens").and_then(json_int_from_value) {
                otel_span.set_attribute(KeyValue::new("gen_ai.usage.total_tokens", value));
                span.record("gen_ai_usage_total_tokens", tracing::field::display(value));
            }
            if let Some(value) = usage
                .get("cached_tokens")
                .and_then(json_int_from_value)
                .or_else(|| {
                    usage
                        .get("prompt_tokens_details")
                        .and_then(|item| item.as_object())
                        .and_then(|item| item.get("cached_tokens"))
                        .and_then(json_int_from_value)
                })
            {
                otel_span.set_attribute(KeyValue::new("gen_ai.usage.cached_tokens", value));
                span.record("gen_ai_usage_cached_tokens", tracing::field::display(value));
            }
            if let Some(value) = usage
                .get("reasoning_tokens")
                .and_then(json_int_from_value)
                .or_else(|| {
                    usage
                        .get("completion_tokens_details")
                        .and_then(|item| item.as_object())
                        .and_then(|item| item.get("reasoning_tokens"))
                        .and_then(json_int_from_value)
                })
                .or_else(|| {
                    usage
                        .get("output_tokens_details")
                        .and_then(|item| item.as_object())
                        .and_then(|item| item.get("reasoning_tokens"))
                        .and_then(json_int_from_value)
                })
            {
                otel_span.set_attribute(KeyValue::new("gen_ai.usage.reasoning_tokens", value));
                span.record(
                    "gen_ai_usage_reasoning_tokens",
                    tracing::field::display(value),
                );
            }
        }

        let finish_reasons = object
            .get("choices")
            .and_then(|item| item.as_array())
            .map(|choices| {
                choices
                    .iter()
                    .filter_map(|choice| choice.get("finish_reason").and_then(|item| item.as_str()))
                    .map(|reason| reason.to_string())
                    .collect::<Vec<_>>()
            })
            .filter(|reasons| !reasons.is_empty())
            .or_else(|| {
                object
                    .get("finish_reason")
                    .and_then(|item| item.as_str())
                    .map(|reason| vec![reason.to_string()])
            });

        if let Some(finish_reasons) = finish_reasons {
            let finish_reasons_json = serde_json::to_string(&finish_reasons).unwrap_or_default();
            otel_span.set_attribute(KeyValue::new(
                "gen_ai.response.finish_reasons",
                Value::Array(Array::String(
                    finish_reasons.iter().cloned().map(Into::into).collect(),
                )),
            ));
            span.record(
                "gen_ai_response_finish_reasons",
                tracing::field::display(&finish_reasons_json),
            );
        }
    }
}

#[cfg(feature = "otlp")]
fn build_provider_id(provider: &str, path: &str, model: Option<&str>) -> String {
    let operation = path
        .trim_start_matches('/')
        .trim_start_matches("v1/")
        .split('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("request");

    match model {
        Some(model) if !model.trim().is_empty() => format!("{provider}:{operation}:{model}"),
        _ => format!("{provider}:{operation}"),
    }
}

#[cfg(feature = "otlp")]
fn json_int(value: Option<&serde_json::Value>) -> Option<i64> {
    value.and_then(json_int_from_value)
}

#[cfg(feature = "otlp")]
fn json_int_from_value(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|item| i64::try_from(item).ok()))
}

#[cfg(feature = "otlp")]
fn json_float(value: Option<&serde_json::Value>) -> Option<f64> {
    value.and_then(|item| item.as_f64())
}

#[cfg(feature = "otlp")]
fn json_string_array(value: &serde_json::Value) -> Option<Vec<String>> {
    match value {
        serde_json::Value::String(item) => Some(vec![item.to_string()]),
        serde_json::Value::Array(items) => {
            let values = items
                .iter()
                .filter_map(|item| item.as_str().map(|text| text.to_string()))
                .collect::<Vec<_>>();
            if values.is_empty() {
                None
            } else {
                Some(values)
            }
        }
        _ => None,
    }
}

#[cfg(feature = "otlp")]
fn truncate_utf8_bytes(body: &Bytes, max_bytes: usize) -> String {
    truncate_utf8_string(&String::from_utf8_lossy(body), max_bytes)
}

#[cfg(feature = "otlp")]
fn truncate_utf8_string(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = max_bytes;
    while !value.is_char_boundary(end) && end > 0 {
        end -= 1;
    }

    format!("{}...(truncated)", &value[..end])
}

#[cfg(feature = "otlp")]
pub fn resolve_otlp_config() -> Option<ResolvedOtlpConfig> {
    if let Ok(endpoint) = std::env::var("VERDICTAN_OTLP_ENDPOINT") {
        let endpoint = endpoint.trim();
        if !endpoint.is_empty() {
            return Some(ResolvedOtlpConfig::ExplicitGrpc {
                endpoint: endpoint.to_string(),
            });
        }
    }
    None
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
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::OnceLock;

    use super::ServiceJsonWriter;
    use tracing_subscriber::fmt::MakeWriter as _;

    #[test]
    fn service_json_writer_injects_service_prefix_for_json_payloads() {
        let mut output = Vec::new();
        let payload = br#"{"level":"info"}"#;
        let written = {
            let mut writer = ServiceJsonWriter {
                inner: &mut output,
                service_prefix_written: false,
            };
            writer.write(payload)
        };

        assert_eq!(written.ok(), Some(payload.len()));
        assert_eq!(output, br#"{"service":"verdictan-cli","level":"info"}"#);
    }

    #[test]
    fn service_json_writer_only_injects_prefix_once_across_chunked_writes() {
        let mut output = Vec::new();
        let first = b"{";
        let second = br#""level":"info"}"#;
        let (first_written, second_written) = {
            let mut writer = ServiceJsonWriter {
                inner: &mut output,
                service_prefix_written: false,
            };
            (writer.write(first), writer.write(second))
        };

        assert_eq!(first_written.ok(), Some(first.len()));
        assert_eq!(second_written.ok(), Some(second.len()));
        assert_eq!(output, br#"{"service":"verdictan-cli","level":"info"}"#);
    }

    #[test]
    fn service_json_writer_passthroughs_non_json_payloads() {
        let mut output = Vec::new();
        let payload = b"plain text log line";
        let written = {
            let mut writer = ServiceJsonWriter {
                inner: &mut output,
                service_prefix_written: false,
            };
            writer.write(payload)
        };

        assert_eq!(written.ok(), Some(payload.len()));
        assert_eq!(output, payload);
    }

    #[test]
    fn service_json_writer_empty_write_returns_zero() {
        let mut output = Vec::new();
        let written = {
            let mut writer = ServiceJsonWriter {
                inner: &mut output,
                service_prefix_written: false,
            };
            writer.write(b"")
        };
        assert_eq!(written.ok(), Some(0));
        assert!(output.is_empty());
    }

    #[test]
    fn service_json_writer_flush_propagates() {
        let mut output = Vec::new();
        let result = {
            let mut writer = ServiceJsonWriter {
                inner: &mut output,
                service_prefix_written: false,
            };
            writer.flush()
        };
        assert!(result.is_ok());
    }

    #[test]
    fn service_json_writer_already_prefixed_no_double_inject() {
        let mut output = Vec::new();
        let payload = br#"{"another":"msg"}"#;
        let written = {
            let mut writer = ServiceJsonWriter {
                inner: &mut output,
                service_prefix_written: true,
            };
            writer.write(payload)
        };
        assert_eq!(written.ok(), Some(payload.len()));
        assert_eq!(output, payload.as_slice());
    }

    #[test]
    fn service_json_writer_non_brace_start_no_prefix() {
        let mut output = Vec::new();
        let payload = b"[1,2,3]";
        let written = {
            let mut writer = ServiceJsonWriter {
                inner: &mut output,
                service_prefix_written: false,
            };
            writer.write(payload)
        };
        assert_eq!(written.ok(), Some(payload.len()));
        assert_eq!(output, payload.as_slice());
    }

    #[test]
    fn service_make_writer_constructs_stdout_json_writer() {
        let _writer = super::ServiceMakeWriter.make_writer();
    }

    #[test]
    fn resolve_json_log_format_defaults_to_text() {
        assert!(!super::resolve_json_log_format(None));
        assert!(!super::resolve_json_log_format(Some("")));
        assert!(!super::resolve_json_log_format(Some("   ")));
        assert!(!super::resolve_json_log_format(Some("text")));
    }

    #[test]
    fn resolve_json_log_format_accepts_trimmed_case_insensitive_json() {
        assert!(super::resolve_json_log_format(Some("json")));
        assert!(super::resolve_json_log_format(Some(" JSON ")));
    }

    #[test]
    fn use_json_log_format_reads_environment_flag() {
        let _guard = crate::test_support::env_lock().lock().expect("env lock");

        std::env::remove_var("VERDICTAN_LOG_FORMAT");
        assert!(!super::use_json_log_format());

        std::env::set_var("VERDICTAN_LOG_FORMAT", " json ");
        assert!(super::use_json_log_format());

        std::env::remove_var("VERDICTAN_LOG_FORMAT");
    }

    #[test]
    fn with_policy_span_returns_closure_value() {
        let value = super::with_policy_span("quality-scorer", "output", |_| 42);
        assert_eq!(value, 42);
    }

    #[test]
    fn annotate_provider_span_records_without_otlp_feature() {
        let span = tracing::info_span!("provider_span_test");
        let _guard = span.enter();
        super::annotate_provider_span(
            &span,
            "req-telemetry-1",
            "openai",
            "/v1/chat/completions",
            "https://api.openai.com",
            Some("gpt-4o"),
        );
    }

    #[test]
    fn attach_parent_trace_context_accepts_traceparent_header() {
        let span = tracing::info_span!("traceparent_span_test");
        super::attach_parent_trace_context(
            &span,
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        );
    }

    #[test]
    fn annotate_workflow_phase_span_is_noop_without_otlp() {
        let span = tracing::info_span!("workflow_phase_span_test");
        super::annotate_workflow_phase_span(&span, "refund-flow", "tool_execution");
    }

    #[test]
    fn annotate_provider_response_attributes_handles_json_body_without_otlp() {
        let span = tracing::info_span!("provider_response_span_test");
        let body = bytes::Bytes::from_static(
            br#"{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15},"choices":[{"finish_reason":"stop"}]}"#,
        );
        super::annotate_provider_response_attributes(
            &span,
            http::StatusCode::OK,
            &body,
            false,
            true,
        );
    }

    #[test]
    fn annotate_provider_request_attributes_handles_chat_body_without_otlp() {
        let span = tracing::info_span!("provider_request_span_test");
        let body = bytes::Bytes::from_static(
            br#"{"model":"gpt-4o","max_tokens":128,"temperature":0.2,"tools":[{"function":{"name":"lookup_order"}}]}"#,
        );
        super::annotate_provider_request_attributes(
            &span,
            "openai",
            "/v1/chat/completions",
            &body,
            false,
            None,
            true,
        );
    }

    #[test]
    fn annotate_policy_result_span_is_noop_without_otlp() {
        use crate::gateway::enforcement::{PolicyResult, Verdict};

        let span = tracing::info_span!("policy_result_span_test");
        let result = PolicyResult {
            policy_kind: "quality-scorer".to_string(),
            phase: "output".to_string(),
            verdict: Verdict::Allow,
            reason_code: "ok".to_string(),
            redaction_targets: None,
            details: Some(serde_json::json!({
                "metrics": {"aggregate": 0.92},
                "thresholds": {"min_aggregate": 0.8},
                "assertions": [{"type": "contains"}],
                "failures": [],
                "tool_names": ["lookup_order"]
            })),
        };
        super::annotate_policy_result_span(&span, &result);
    }

    #[test]
    fn annotate_score_span_attributes_is_noop_without_otlp() {
        use crate::policy::llm_judge::{JudgeResult, JudgeVerdict};

        let span = tracing::info_span!("score_span_test");
        let judge = JudgeResult {
            scorer_name: "quality-judge".to_string(),
            scorer_model: "gpt-5.4-mini".to_string(),
            scorer_version: "1".to_string(),
            score: 0.91,
            threshold: 0.8,
            verdict: JudgeVerdict::Pass,
            rationale: Some("clear response".to_string()),
            sampled: true,
        };
        super::annotate_score_span_attributes(&span, &judge, Some(42));
    }

    #[test]
    fn init_once_runs_initializer_only_once() {
        let state = OnceLock::new();
        let calls = AtomicUsize::new(0);

        super::init_once(&state, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<(), &'static str>(())
        })
        .expect("first init");
        super::init_once(&state, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>("should not run")
        })
        .expect("cached init");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn init_once_reuses_cached_error() {
        let state = OnceLock::new();
        let calls = AtomicUsize::new(0);

        let first = super::init_once(&state, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>("init failed")
        });
        let second = super::init_once(&state, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<(), &'static str>(())
        });

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(format!("{}", first.expect_err("first init should fail")).contains("init failed"));
        assert!(format!("{}", second.expect_err("cached init should fail")).contains("init failed"));
    }

    #[cfg(feature = "otlp")]
    mod otlp_feature_tests {
        use super::super::{
            annotate_policy_result_span, annotate_provider_request_attributes,
            annotate_provider_response_attributes, annotate_provider_span,
            annotate_score_span_attributes, annotate_workflow_phase_span,
            attach_parent_trace_context, deployment_environment, resolve_otlp_config,
            ResolvedOtlpConfig,
        };
        use crate::config::test_env_lock;
        use crate::gateway::enforcement::{PolicyResult, Verdict};
        use crate::policy::llm_judge::{JudgeResult, JudgeVerdict};
        use bytes::Bytes;
        use http::StatusCode;
        use serial_test::serial;

        #[test]
        #[serial]
        fn resolve_otlp_config_rejects_blank_endpoint() {
            let _guard = test_env_lock().lock().expect("env lock");
            std::env::set_var("VERDICTAN_OTLP_ENDPOINT", "   ");
            assert!(resolve_otlp_config().is_none());
            std::env::remove_var("VERDICTAN_OTLP_ENDPOINT");
        }

        #[test]
        #[serial]
        fn resolve_otlp_config_trims_endpoint_whitespace() {
            let _guard = test_env_lock().lock().expect("env lock");
            std::env::set_var("VERDICTAN_OTLP_ENDPOINT", "  http://127.0.0.1:4317  ");
            let resolved = resolve_otlp_config().expect("resolved otlp config");
            match resolved {
                ResolvedOtlpConfig::ExplicitGrpc { endpoint } => {
                    assert_eq!(endpoint, "http://127.0.0.1:4317");
                }
            }
            std::env::remove_var("VERDICTAN_OTLP_ENDPOINT");
        }

        #[test]
        #[serial]
        fn deployment_environment_requires_verdictan_env() {
            let _guard = test_env_lock().lock().expect("env lock");
            std::env::remove_var("VERDICTAN_ENV");
            let error = deployment_environment().expect_err("missing VERDICTAN_ENV should fail");
            assert!(error
                .to_string()
                .contains("VERDICTAN_ENV must be set for CLI telemetry"));
        }

        #[test]
        #[serial]
        fn deployment_environment_uses_verdictan_env() {
            let _guard = test_env_lock().lock().expect("env lock");
            std::env::set_var("VERDICTAN_ENV", "production");
            let environment = deployment_environment().expect("deployment environment");
            assert_eq!(environment, "production");
            std::env::remove_var("VERDICTAN_ENV");
        }

        #[test]
        fn otlp_span_annotators_execute_with_full_payloads() {
            let span = tracing::info_span!("otlp_span_bundle");
            let _guard = span.enter();

            annotate_workflow_phase_span(&span, "refund-flow", "tool_execution");
            attach_parent_trace_context(
                &span,
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            );
            annotate_provider_span(
                &span,
                "req-otlp-1",
                "openai",
                "/v1/chat/completions",
                "https://api.openai.com",
                Some("gpt-4o"),
            );

            let policy = PolicyResult {
                policy_kind: "quality-scorer".to_string(),
                phase: "output".to_string(),
                verdict: Verdict::Block,
                reason_code: "threshold".to_string(),
                redaction_targets: None,
                details: Some(serde_json::json!({
                    "metrics": {"aggregate": 0.42},
                    "thresholds": {"min_aggregate": 0.8},
                    "assertions": [{"type": "contains"}],
                    "failures": [{"type": "missing"}],
                    "tool_names": ["lookup_order", "refund"]
                })),
            };
            annotate_policy_result_span(&span, &policy);

            let judge = JudgeResult {
                scorer_name: "quality-judge".to_string(),
                scorer_model: "gpt-5.4-mini".to_string(),
                scorer_version: "1".to_string(),
                score: 0.91,
                threshold: 0.8,
                verdict: JudgeVerdict::Pass,
                rationale: Some("clear response".to_string()),
                sampled: true,
            };
            annotate_score_span_attributes(&span, &judge, Some(128));

            let request_body = Bytes::from_static(
                br#"{
                    "model":"gpt-4o",
                    "max_tokens":256,
                    "temperature":0.3,
                    "top_p":0.9,
                    "stop":["END"],
                    "tools":[{"function":{"name":"lookup_order"}}],
                    "verdictan": {
                        "prompt": {"label": "refund-assistant"},
                        "test": {"index": 2},
                        "trajectory": [{"step": 1}, {"step": 2}],
                        "trace": {"hint": true}
                    }
                }"#,
            );
            annotate_provider_request_attributes(
                &span,
                "openai",
                "/v1/chat/completions",
                &request_body,
                false,
                None,
                true,
            );
            annotate_provider_request_attributes(
                &span,
                "openai",
                "/v1/chat/completions",
                &Bytes::from_static(b"not-json"),
                true,
                None,
                true,
            );

            let response_body = Bytes::from_static(
                br#"{
                    "usage": {
                        "prompt_tokens": 12,
                        "completion_tokens": 8,
                        "total_tokens": 20,
                        "prompt_tokens_details": {"cached_tokens": 3},
                        "completion_tokens_details": {"reasoning_tokens": 2}
                    },
                    "choices": [{"finish_reason": "stop"}]
                }"#,
            );
            annotate_provider_response_attributes(
                &span,
                StatusCode::OK,
                &response_body,
                false,
                true,
            );
        }

        #[tokio::test]
        #[serial]
        async fn init_with_otlp_endpoint_installs_subscriber() {
            let _guard = test_env_lock().lock().expect("env lock");
            std::env::set_var("VERDICTAN_ENV", "test");
            std::env::set_var("VERDICTAN_OTLP_ENDPOINT", "http://127.0.0.1:4317");
            super::super::init(true).expect("otlp telemetry init");
            std::env::remove_var("VERDICTAN_ENV");
            std::env::remove_var("VERDICTAN_OTLP_ENDPOINT");
        }

        #[tokio::test]
        #[serial]
        async fn init_with_json_log_format_and_otlp_endpoint() {
            let _guard = test_env_lock().lock().expect("env lock");
            std::env::set_var("VERDICTAN_ENV", "test");
            std::env::set_var("VERDICTAN_LOG_FORMAT", "json");
            std::env::set_var("VERDICTAN_OTLP_ENDPOINT", "http://127.0.0.1:4317");
            super::super::init(true).expect("json otlp telemetry init");
            std::env::remove_var("VERDICTAN_ENV");
            std::env::remove_var("VERDICTAN_LOG_FORMAT");
            std::env::remove_var("VERDICTAN_OTLP_ENDPOINT");
        }
    }
}
