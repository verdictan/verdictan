// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Prometheus metrics definitions for the gateway.
//!
//! All metrics are registered on the default global prometheus registry so
//! they are automatically gathered by `prometheus::gather` and served at
//! the unauthenticated `GET /metrics` endpoint.
//!
//! Metric naming follows the `verdictan_gateway_` prefix convention for the
//! Verdictan gateway process, except for the audit WAL delivery
//! metrics which use the exact `audit_*` names required by audit WAL acceptance.

use chrono::{DateTime, Utc};
use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_histogram,
    register_histogram_vec, Counter, CounterVec, Gauge, Histogram, HistogramVec,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

use crate::gateway::event_wal::{self, WalConfig, WalWriter, DURABLE_REQUEST_RESERVATION_BYTES};

// ---------------------------------------------------------------------------
// verdictan_gateway_requests_total — total requests routed through the gateway
// ---------------------------------------------------------------------------

/// Total requests processed by the gateway, labelled by HTTP method, response
/// status code bucket, and upstream provider name.
pub(crate) static REQUEST_COUNTER: LazyLock<CounterVec> = LazyLock::new(|| {
    // SAFETY: invariant: metric registration happens exactly once during Lazy initialization.
    #[allow(clippy::expect_used)]
    let counter = register_counter_vec!(
        "verdictan_gateway_requests_total",
        "Total gateway requests",
        &["method", "status", "provider"]
    )
    .expect("invariant: verdictan_gateway_requests_total must register exactly once");
    counter
});

// ---------------------------------------------------------------------------
// verdictan_gateway_policy_eval_duration_seconds — policy chain latency
// ---------------------------------------------------------------------------

/// Histogram of policy-chain evaluation latency in seconds.
pub(crate) static POLICY_EVAL_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
    // SAFETY: invariant: metric registration happens exactly once during Lazy initialization.
    #[allow(clippy::expect_used)]
    let histogram = register_histogram!(
        "verdictan_gateway_policy_eval_duration_seconds",
        "Gateway policy evaluation duration in seconds"
    )
    .expect("invariant: verdictan_gateway_policy_eval_duration_seconds must register exactly once");
    histogram
});

// ---------------------------------------------------------------------------
// verdictan_gateway_upstream_errors_total — upstream provider errors
// ---------------------------------------------------------------------------

/// Count of errors returned by upstream LLM providers, labelled by provider
/// name and error type (e.g. `timeout`, `rate_limited`, `server_error`).
pub(crate) static UPSTREAM_ERROR_COUNTER: LazyLock<CounterVec> = LazyLock::new(|| {
    // SAFETY: invariant: metric registration happens exactly once during Lazy initialization.
    #[allow(clippy::expect_used)]
    let counter = register_counter_vec!(
        "verdictan_gateway_upstream_errors_total",
        "Total upstream provider errors",
        &["provider", "error_type"]
    )
    .expect("invariant: verdictan_gateway_upstream_errors_total must register exactly once");
    counter
});

// ---------------------------------------------------------------------------
// verdictan_gateway_cache_hits_total / verdictan_gateway_cache_misses_total
// ---------------------------------------------------------------------------

/// Number of provider response cache hits.
pub(crate) static CACHE_HIT_COUNTER: LazyLock<Counter> = LazyLock::new(|| {
    // SAFETY: invariant: metric registration happens exactly once during Lazy initialization.
    #[allow(clippy::expect_used)]
    let counter = register_counter!(
        "verdictan_gateway_cache_hits_total",
        "Total gateway response cache hits"
    )
    .expect("invariant: verdictan_gateway_cache_hits_total must register exactly once");
    counter
});

/// Number of provider response cache misses.
pub(crate) static CACHE_MISS_COUNTER: LazyLock<Counter> = LazyLock::new(|| {
    // SAFETY: invariant: metric registration happens exactly once during Lazy initialization.
    #[allow(clippy::expect_used)]
    let counter = register_counter!(
        "verdictan_gateway_cache_misses_total",
        "Total gateway response cache misses"
    )
    .expect("invariant: verdictan_gateway_cache_misses_total must register exactly once");
    counter
});

// ---------------------------------------------------------------------------
// verdictan_gateway_events_dropped_total — events lost to backpressure
// ---------------------------------------------------------------------------

/// CLI-LOGIC-003: Counter for events dropped due to forwarding backpressure.
pub(crate) static EVENTS_DROPPED_COUNTER: LazyLock<Counter> = LazyLock::new(|| {
    // SAFETY: invariant: metric registration happens exactly once during Lazy initialization.
    #[allow(clippy::expect_used)]
    let counter = register_counter!(
        "verdictan_gateway_events_dropped_total",
        "Total gateway events dropped due to forwarding backpressure"
    )
    .expect("invariant: verdictan_gateway_events_dropped_total must register exactly once");
    counter
});

// ---------------------------------------------------------------------------
// verdictan_gateway_active_connections — live in-flight requests
// ---------------------------------------------------------------------------

/// Current number of in-flight requests being proxied by the gateway.
pub(crate) static ACTIVE_CONNECTIONS: LazyLock<Gauge> = LazyLock::new(|| {
    // SAFETY: invariant: metric registration happens exactly once during Lazy initialization.
    #[allow(clippy::expect_used)]
    let gauge = register_gauge!(
        "verdictan_gateway_active_connections",
        "Current number of active gateway connections"
    )
    .expect("invariant: verdictan_gateway_active_connections must register exactly once");
    gauge
});

// ---------------------------------------------------------------------------
// verdictan_gateway_usage_authorization_control_plane_total — control-plane calls
// ---------------------------------------------------------------------------

/// Count usage-authorization control-plane calls, labelled by operation and outcome.
pub(crate) static USAGE_AUTHORIZATION_CONTROL_PLANE_COUNTER: LazyLock<CounterVec> = LazyLock::new(
    || {
        // SAFETY: invariant: metric registration happens exactly once during Lazy initialization.
        #[allow(clippy::expect_used)]
        let counter = register_counter_vec!(
            "verdictan_gateway_usage_authorization_control_plane_total",
            "Total usage-authorization control-plane calls",
            &["operation", "outcome"]
        )
        .expect(
            "invariant: verdictan_gateway_usage_authorization_control_plane_total must register exactly once",
        );
        counter
    },
);

// ---------------------------------------------------------------------------
// verdictan_gateway_relay_requests_total — relay requests processed
// ---------------------------------------------------------------------------

/// Total relay requests processed by this gateway, labelled by outcome.
pub(crate) static RELAY_REQUEST_COUNTER: LazyLock<CounterVec> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    let counter = register_counter_vec!(
        "verdictan_gateway_relay_requests_total",
        "Total gateway relay requests",
        &["direction", "outcome"]
    )
    .expect("invariant: verdictan_gateway_relay_requests_total must register exactly once");
    counter
});

// ---------------------------------------------------------------------------
// verdictan_gateway_relay_duration_seconds — relay round-trip latency
// ---------------------------------------------------------------------------

/// Histogram of relay request latency in seconds, labelled by direction.
pub(crate) static RELAY_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    let histogram = register_histogram_vec!(
        "verdictan_gateway_relay_duration_seconds",
        "Gateway relay request duration in seconds",
        &["direction"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
    )
    .expect("invariant: verdictan_gateway_relay_duration_seconds must register exactly once");
    histogram
});

// ---------------------------------------------------------------------------
// audit WAL / delivery metrics (exact acceptance names)
// ---------------------------------------------------------------------------

/// Durable records currently occupying the audit event WAL.
pub(crate) static AUDIT_WAL_RECORDS: LazyLock<Gauge> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_gauge!(
        "audit_wal_records",
        "Durable records currently stored in the gateway audit event WAL"
    )
    .expect("invariant: audit_wal_records must register exactly once")
});

/// Durable bytes currently occupying the audit event WAL.
pub(crate) static AUDIT_WAL_BYTES: LazyLock<Gauge> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_gauge!(
        "audit_wal_bytes",
        "Durable bytes currently stored in the gateway audit event WAL"
    )
    .expect("invariant: audit_wal_bytes must register exactly once")
});

/// Age in seconds of the oldest unacknowledged audit WAL record.
pub(crate) static AUDIT_WAL_OLDEST_AGE_SECONDS: LazyLock<Gauge> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_gauge!(
        "audit_wal_oldest_age_seconds",
        "Age in seconds of the oldest unacknowledged audit WAL record"
    )
    .expect("invariant: audit_wal_oldest_age_seconds must register exactly once")
});

/// Total audit delivery retries (network/408/429/5xx replay attempts).
pub(crate) static AUDIT_DELIVERY_RETRIES_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_counter!(
        "audit_delivery_retries_total",
        "Total audit WAL delivery retry attempts"
    )
    .expect("invariant: audit_delivery_retries_total must register exactly once")
});

/// Total audit delivery quarantine events (permanent reject / corrupt record).
pub(crate) static AUDIT_DELIVERY_QUARANTINE_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_counter!(
        "audit_delivery_quarantine_total",
        "Total audit WAL delivery quarantine events"
    )
    .expect("invariant: audit_delivery_quarantine_total must register exactly once")
});

/// Unix timestamp of the last successful audit delivery acknowledgement.
pub(crate) static AUDIT_DELIVERY_LAST_SUCCESS_TIMESTAMP: LazyLock<Gauge> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_gauge!(
        "audit_delivery_last_success_timestamp",
        "Unix timestamp of the last successful audit WAL delivery"
    )
    .expect("invariant: audit_delivery_last_success_timestamp must register exactly once")
});

/// Process-local mirror for last-success timestamp (Gauge get is not always convenient).
static AUDIT_DELIVERY_LAST_SUCCESS_UNIX: AtomicU64 = AtomicU64::new(0);

/// Read-only observation of audit WAL durability health and metric values.
///
/// This is the shared surface between Prometheus exposure and `/readyz`. The
/// delivery worker may update retry/quarantine/success counters via the
/// `record_audit_delivery_*` helpers without exposing worker internals.
#[derive(Debug, Clone)]
pub(crate) struct AuditWalSnapshot {
    pub audit_wal_records: u64,
    pub audit_wal_bytes: u64,
    pub audit_wal_oldest_age_seconds: f64,
    pub audit_delivery_retries_total: f64,
    pub audit_delivery_quarantine_total: f64,
    pub audit_delivery_last_success_timestamp: f64,
    pub wal_full: bool,
    pub wal_unwritable: bool,
    pub corrupt_checkpoint: bool,
    pub quarantine_non_empty: bool,
    pub quarantine_files: u64,
    pub wal_dir: PathBuf,
}

impl AuditWalSnapshot {
    /// Serialize the six required audit metrics for readiness/metrics JSON.
    pub(crate) fn metrics_json(&self) -> serde_json::Value {
        serde_json::json!({
            "audit_wal_records": self.audit_wal_records,
            "audit_wal_bytes": self.audit_wal_bytes,
            "audit_wal_oldest_age_seconds": self.audit_wal_oldest_age_seconds,
            "audit_delivery_retries_total": self.audit_delivery_retries_total,
            "audit_delivery_quarantine_total": self.audit_delivery_quarantine_total,
            "audit_delivery_last_success_timestamp": self.audit_delivery_last_success_timestamp,
        })
    }

    /// True when audit-required readiness must return 503.
    pub(crate) fn readiness_blocked(&self) -> bool {
        self.wal_full || self.wal_unwritable || self.corrupt_checkpoint || self.quarantine_non_empty
    }
}

/// Resolve the configured audit WAL directory from `VERDICTAN_DATA_DIR`.
pub(crate) fn audit_wal_data_dir() -> PathBuf {
    std::env::var("VERDICTAN_DATA_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("verdictan"))
}

/// Observe the on-disk audit WAL and refresh Prometheus gauges.
///
/// Read-only with respect to the delivery worker: opens a recovery view of the
/// WAL directory and inspects checkpoint / quarantine / occupancy. Delivery
/// counters are process-local and updated only through the record helpers.
pub(crate) fn observe_audit_wal() -> AuditWalSnapshot {
    observe_audit_wal_at(&audit_wal_data_dir())
}

/// Observe a specific data-dir root (`<data_dir>/event-retry`).
pub(crate) fn observe_audit_wal_at(data_dir: &Path) -> AuditWalSnapshot {
    match WalConfig::new(data_dir) {
        Ok(config) => observe_audit_wal_config(config),
        Err(_) => {
            let wal_dir = data_dir.join("event-retry");
            let (quarantine_non_empty, quarantine_files) = quarantine_file_count(&wal_dir);
            let snapshot = AuditWalSnapshot {
                audit_wal_records: 0,
                audit_wal_bytes: 0,
                audit_wal_oldest_age_seconds: 0.0,
                audit_delivery_retries_total: AUDIT_DELIVERY_RETRIES_TOTAL.get(),
                audit_delivery_quarantine_total: AUDIT_DELIVERY_QUARANTINE_TOTAL.get(),
                audit_delivery_last_success_timestamp: AUDIT_DELIVERY_LAST_SUCCESS_UNIX
                    .load(Ordering::Relaxed)
                    as f64,
                wal_full: false,
                wal_unwritable: true,
                corrupt_checkpoint: false,
                quarantine_non_empty,
                quarantine_files,
                wal_dir,
            };
            apply_audit_wal_gauges(&snapshot);
            snapshot
        }
    }
}

/// Observe an explicit WAL configuration (shared read-only surface).
pub(crate) fn observe_audit_wal_config(config: WalConfig) -> AuditWalSnapshot {
    let wal_dir = config.dir.clone();
    let wal_unwritable = !probe_wal_writable(&wal_dir);
    let corrupt_checkpoint = match event_wal::load_checkpoint(&wal_dir) {
        Ok(_) => false,
        Err(error) => error.kind() == std::io::ErrorKind::InvalidData,
    };
    let (quarantine_non_empty, quarantine_files) = quarantine_file_count(&wal_dir);

    let mut records = 0u64;
    let mut bytes = 0u64;
    let mut oldest_age = 0.0_f64;
    let mut wal_full = false;

    if !corrupt_checkpoint {
        match WalWriter::open(config.clone()) {
            Ok(writer) => {
                records = writer.records_written();
                bytes = writer.total_bytes();
                oldest_age = oldest_pending_age_seconds(&writer);
                let occupied = bytes.saturating_add(writer.reserved_bytes());
                wal_full = occupied.saturating_add(DURABLE_REQUEST_RESERVATION_BYTES)
                    > config.total_bytes
                    || occupied >= config.total_bytes;
            }
            Err(_) => {
                // Open failure after a valid checkpoint is treated as unwritable
                // in combination with the explicit writability probe.
            }
        }
    }

    let snapshot = AuditWalSnapshot {
        audit_wal_records: records,
        audit_wal_bytes: bytes,
        audit_wal_oldest_age_seconds: oldest_age,
        audit_delivery_retries_total: AUDIT_DELIVERY_RETRIES_TOTAL.get(),
        audit_delivery_quarantine_total: AUDIT_DELIVERY_QUARANTINE_TOTAL.get(),
        audit_delivery_last_success_timestamp: AUDIT_DELIVERY_LAST_SUCCESS_UNIX
            .load(Ordering::Relaxed) as f64,
        wal_full,
        wal_unwritable,
        corrupt_checkpoint,
        quarantine_non_empty,
        quarantine_files,
        wal_dir,
    };
    apply_audit_wal_gauges(&snapshot);
    snapshot
}

fn apply_audit_wal_gauges(snapshot: &AuditWalSnapshot) {
    AUDIT_WAL_RECORDS.set(snapshot.audit_wal_records as f64);
    AUDIT_WAL_BYTES.set(snapshot.audit_wal_bytes as f64);
    AUDIT_WAL_OLDEST_AGE_SECONDS.set(snapshot.audit_wal_oldest_age_seconds);
    AUDIT_DELIVERY_LAST_SUCCESS_TIMESTAMP.set(snapshot.audit_delivery_last_success_timestamp);
}

fn probe_wal_writable(dir: &Path) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".audit-wal-writability-probe");
    let writable = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&probe)?;
        file.write_all(b"ok")?;
        file.sync_all()?;
        Ok(())
    })()
    .is_ok();
    let _ = fs::remove_file(&probe);
    writable
}

fn quarantine_file_count(wal_dir: &Path) -> (bool, u64) {
    let quarantine_dir = wal_dir.join("quarantine");
    let Ok(entries) = fs::read_dir(&quarantine_dir) else {
        return (false, 0);
    };
    let mut count = 0u64;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        if entry
            .file_type()
            .map(|kind| kind.is_file())
            .unwrap_or(false)
        {
            count = count.saturating_add(1);
        }
    }
    (count > 0, count)
}

fn oldest_pending_age_seconds(writer: &WalWriter) -> f64 {
    let Ok(checkpoint) = writer.checkpoint() else {
        return 0.0;
    };
    let Ok(records) = writer.read_from(&checkpoint, 1) else {
        return 0.0;
    };
    let Some(record) = records.first() else {
        return 0.0;
    };
    match DateTime::parse_from_rfc3339(&record.timestamp) {
        Ok(parsed) => {
            let age = Utc::now().signed_duration_since(parsed.with_timezone(&Utc));
            age.num_seconds().max(0) as f64
        }
        Err(_) => 0.0,
    }
}

/// Increment `audit_delivery_retries_total` (delivery worker / tests).
pub(crate) fn record_audit_delivery_retry() {
    AUDIT_DELIVERY_RETRIES_TOTAL.inc();
}

/// Increment `audit_delivery_quarantine_total` (delivery worker / tests).
pub(crate) fn record_audit_delivery_quarantine() {
    AUDIT_DELIVERY_QUARANTINE_TOTAL.inc();
}

/// Record a successful audit delivery acknowledgement timestamp.
pub(crate) fn record_audit_delivery_success() {
    let now = Utc::now().timestamp().max(0) as u64;
    AUDIT_DELIVERY_LAST_SUCCESS_UNIX.store(now, Ordering::Relaxed);
    AUDIT_DELIVERY_LAST_SUCCESS_TIMESTAMP.set(now as f64);
}

/// Force-initialize all Lazy metric statics so they register with the
/// global prometheus registry at gateway startup. Without this call the
/// metrics only appear after the first request exercises each code path.
pub(crate) fn init() {
    LazyLock::force(&REQUEST_COUNTER);
    LazyLock::force(&POLICY_EVAL_DURATION);
    LazyLock::force(&UPSTREAM_ERROR_COUNTER);
    LazyLock::force(&CACHE_HIT_COUNTER);
    LazyLock::force(&CACHE_MISS_COUNTER);
    LazyLock::force(&EVENTS_DROPPED_COUNTER);
    LazyLock::force(&ACTIVE_CONNECTIONS);
    LazyLock::force(&USAGE_AUTHORIZATION_CONTROL_PLANE_COUNTER);
    LazyLock::force(&RELAY_REQUEST_COUNTER);
    LazyLock::force(&RELAY_DURATION);
    LazyLock::force(&AUDIT_WAL_RECORDS);
    LazyLock::force(&AUDIT_WAL_BYTES);
    LazyLock::force(&AUDIT_WAL_OLDEST_AGE_SECONDS);
    LazyLock::force(&AUDIT_DELIVERY_RETRIES_TOTAL);
    LazyLock::force(&AUDIT_DELIVERY_QUARANTINE_TOTAL);
    LazyLock::force(&AUDIT_DELIVERY_LAST_SUCCESS_TIMESTAMP);
    let _ = observe_audit_wal();
}

/// Record a completed gateway request in the Prometheus counters.
pub(crate) fn record_request(method: &str, status: u16, provider: &str) {
    let status_bucket = match status {
        200..=299 => "2xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };
    REQUEST_COUNTER
        .with_label_values(&[method, status_bucket, provider])
        .inc();
}

pub(crate) fn record_usage_authorization_control_plane(operation: &str, outcome: &str) {
    USAGE_AUTHORIZATION_CONTROL_PLANE_COUNTER
        .with_label_values(&[operation, outcome])
        .inc();
}

/// Record a completed relay request with its latency.
pub(crate) fn record_relay_request(latency_ms: u64) {
    RELAY_REQUEST_COUNTER
        .with_label_values(&["inbound", "completed"])
        .inc();
    RELAY_DURATION
        .with_label_values(&["inbound"])
        .observe(latency_ms as f64 / 1000.0);
}

/// Record an outbound relay attempt with its latency and outcome.
pub(crate) fn record_outbound_relay(latency_ms: u64, outcome: &str) {
    RELAY_REQUEST_COUNTER
        .with_label_values(&["outbound", outcome])
        .inc();
    RELAY_DURATION
        .with_label_values(&["outbound"])
        .observe(latency_ms as f64 / 1000.0);
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

    #[test]
    fn init_does_not_panic() {
        init();
        assert!(CACHE_HIT_COUNTER.get() >= 0.0);
        assert!(CACHE_MISS_COUNTER.get() >= 0.0);
        assert!(EVENTS_DROPPED_COUNTER.get() >= 0.0);
        assert!(ACTIVE_CONNECTIONS.get() >= 0.0);
    }

    #[test]
    fn record_request_2xx_bucket() {
        let before = REQUEST_COUNTER
            .with_label_values(&["GET", "2xx", "openai"])
            .get();
        record_request("GET", 200, "openai");
        let after = REQUEST_COUNTER
            .with_label_values(&["GET", "2xx", "openai"])
            .get();
        assert!((after - before - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn record_request_4xx_bucket() {
        let before = REQUEST_COUNTER
            .with_label_values(&["POST", "4xx", "openai"])
            .get();
        record_request("POST", 429, "openai");
        let after = REQUEST_COUNTER
            .with_label_values(&["POST", "4xx", "openai"])
            .get();
        assert!((after - before - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn record_request_5xx_bucket() {
        let before = REQUEST_COUNTER
            .with_label_values(&["POST", "5xx", "test"])
            .get();
        record_request("POST", 500, "test");
        let after = REQUEST_COUNTER
            .with_label_values(&["POST", "5xx", "test"])
            .get();
        assert!((after - before - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn record_request_other_bucket() {
        let before = REQUEST_COUNTER
            .with_label_values(&["GET", "other", "test"])
            .get();
        record_request("GET", 301, "test");
        let after = REQUEST_COUNTER
            .with_label_values(&["GET", "other", "test"])
            .get();
        assert!((after - before - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn record_usage_authorization_control_plane_increments() {
        let before = USAGE_AUTHORIZATION_CONTROL_PLANE_COUNTER
            .with_label_values(&["validate", "success"])
            .get();
        record_usage_authorization_control_plane("validate", "success");
        let after = USAGE_AUTHORIZATION_CONTROL_PLANE_COUNTER
            .with_label_values(&["validate", "success"])
            .get();
        assert!((after - before - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn record_relay_request_increments() {
        let before = RELAY_REQUEST_COUNTER
            .with_label_values(&["inbound", "completed"])
            .get();
        record_relay_request(150);
        let after = RELAY_REQUEST_COUNTER
            .with_label_values(&["inbound", "completed"])
            .get();
        assert!((after - before - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn record_outbound_relay_increments() {
        let before = RELAY_REQUEST_COUNTER
            .with_label_values(&["outbound", "ok"])
            .get();
        record_outbound_relay(200, "ok");
        let after = RELAY_REQUEST_COUNTER
            .with_label_values(&["outbound", "ok"])
            .get();
        assert!((after - before - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn events_dropped_counter_increments() {
        let before = EVENTS_DROPPED_COUNTER.get();
        EVENTS_DROPPED_COUNTER.inc();
        assert!((EVENTS_DROPPED_COUNTER.get() - before - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn active_connections_gauge() {
        ACTIVE_CONNECTIONS.set(5.0);
        assert!((ACTIVE_CONNECTIONS.get() - 5.0).abs() < f64::EPSILON);
        ACTIVE_CONNECTIONS.set(0.0);
    }

    #[test]
    fn policy_eval_duration_observe() {
        let before = POLICY_EVAL_DURATION.get_sample_count();
        POLICY_EVAL_DURATION.observe(0.05);
        assert_eq!(POLICY_EVAL_DURATION.get_sample_count(), before + 1);
    }

    #[test]
    fn audit_delivery_counters_and_success_timestamp_update() {
        init();
        let retries_before = AUDIT_DELIVERY_RETRIES_TOTAL.get();
        let quarantine_before = AUDIT_DELIVERY_QUARANTINE_TOTAL.get();
        record_audit_delivery_retry();
        record_audit_delivery_quarantine();
        record_audit_delivery_success();
        assert!((AUDIT_DELIVERY_RETRIES_TOTAL.get() - retries_before - 1.0).abs() < f64::EPSILON);
        assert!(
            (AUDIT_DELIVERY_QUARANTINE_TOTAL.get() - quarantine_before - 1.0).abs() < f64::EPSILON
        );
        assert!(AUDIT_DELIVERY_LAST_SUCCESS_TIMESTAMP.get() > 0.0);
        let snapshot = observe_audit_wal();
        assert!(snapshot.audit_delivery_retries_total >= retries_before + 1.0);
        assert!(snapshot.audit_delivery_quarantine_total >= quarantine_before + 1.0);
        assert!(snapshot.audit_delivery_last_success_timestamp > 0.0);
        let json = snapshot.metrics_json();
        assert!(json.get("audit_wal_records").is_some());
        assert!(json.get("audit_wal_bytes").is_some());
        assert!(json.get("audit_wal_oldest_age_seconds").is_some());
        assert!(json.get("audit_delivery_retries_total").is_some());
        assert!(json.get("audit_delivery_quarantine_total").is_some());
        assert!(json.get("audit_delivery_last_success_timestamp").is_some());
    }

    #[test]
    fn observe_audit_wal_reports_records_bytes_and_oldest_age() {
        init();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let config = event_wal::WalConfig {
            dir: tmp.path().join("event-retry"),
            total_bytes: 1_048_576,
            segment_bytes: 4_096,
            delivery_pool: 1,
            fs_pool: 1,
        };
        let mut writer = WalWriter::open(config).expect("open wal");
        let payload = serde_json::json!({
            "delivery_id": "d1",
            "event_id": "e1",
            "event_kind": "decision",
        });
        // Append through the writer API which stamps its own timestamp; age should be ~0.
        writer
            .append("e1".to_string(), payload)
            .expect("append wal record");
        drop(writer);

        let snapshot = observe_audit_wal_at(tmp.path());
        assert_eq!(snapshot.audit_wal_records, 1);
        assert!(snapshot.audit_wal_bytes > 0);
        assert!(snapshot.audit_wal_oldest_age_seconds >= 0.0);
        assert!(!snapshot.readiness_blocked());
        assert!((AUDIT_WAL_RECORDS.get() - 1.0).abs() < f64::EPSILON);
        assert!(AUDIT_WAL_BYTES.get() > 0.0);
    }

    #[test]
    fn observe_audit_wal_detects_non_empty_quarantine() {
        init();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let wal_dir = tmp.path().join("event-retry");
        let quarantine = wal_dir.join("quarantine");
        std::fs::create_dir_all(&quarantine).expect("quarantine dir");
        std::fs::write(
            quarantine.join("permanent-segment-0000000000-offset-00000000000000000000.json"),
            b"{}",
        )
        .expect("quarantine file");
        let snapshot = observe_audit_wal_at(tmp.path());
        assert!(snapshot.quarantine_non_empty);
        assert_eq!(snapshot.quarantine_files, 1);
        assert!(snapshot.readiness_blocked());
    }

    #[test]
    fn observe_audit_wal_detects_corrupt_checkpoint() {
        init();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let wal_dir = tmp.path().join("event-retry");
        std::fs::create_dir_all(&wal_dir).expect("wal dir");
        std::fs::write(wal_dir.join("checkpoint.json"), "{not-json").expect("bad checkpoint");
        let snapshot = observe_audit_wal_at(tmp.path());
        assert!(snapshot.corrupt_checkpoint);
        assert!(snapshot.readiness_blocked());
    }

    #[test]
    fn observe_audit_wal_detects_full_capacity() {
        init();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        // Tiny WAL that cannot accept a 2 MiB admission reservation.
        let config = WalConfig {
            dir: tmp.path().join("event-retry"),
            total_bytes: 1_024,
            segment_bytes: 1_024,
            delivery_pool: 1,
            fs_pool: 1,
        };
        let _writer = WalWriter::open(config.clone()).expect("open");
        let snapshot = observe_audit_wal_config(config);
        assert!(
            snapshot.wal_full,
            "tiny WAL must be full relative to reservation"
        );
        assert!(snapshot.readiness_blocked());
    }
}
