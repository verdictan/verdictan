// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Bounded shadow-evaluation worker queue.
//!
//! Replaces per-request `tokio::spawn` for shadow evaluation with a fixed
//! worker pool (8), an item cap (256), and a cloned-payload byte cap (16 MiB).
//! Overflow is recorded via drop counters; shutdown cancels queued and
//! in-flight work.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use axum::http::{header::HeaderValue, StatusCode};
use tokio::sync::{mpsc, watch, Notify};

use crate::gateway::providers::ProviderTarget;
use crate::gateway::server::event_delivery::EventSink;

/// Fixed worker pool size for delayed shadow evaluation.
pub const SHADOW_WORKER_COUNT: usize = 8;
/// Maximum queued shadow jobs (not counting in-flight worker slots).
pub const SHADOW_QUEUE_CAPACITY: usize = 256;
/// Maximum total cloned payload bytes held in the queue.
pub const SHADOW_QUEUE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Why a shadow job was dropped before a worker claimed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowQueueDropReason {
    ItemLimit,
    ByteLimit,
    Shutdown,
}

/// Owned work unit for one delayed shadow evaluation.
#[derive(Debug)]
pub struct ShadowEvaluationJob {
    pub client: reqwest::Client,
    pub target: ProviderTarget,
    pub path: String,
    pub request_id: String,
    pub traceparent: String,
    pub content_type: Option<HeaderValue>,
    pub request_json: serde_json::Value,
    pub capture_mode: String,
    pub event_sink: Option<EventSink>,
    pub primary_provider_id: String,
    pub request_family: String,
    pub decision_id: String,
    /// Counted cloned-payload bytes reserved against the queue budget.
    pub payload_bytes: usize,
}

impl ShadowEvaluationJob {
    /// Estimate cloned payload bytes for admission accounting.
    pub fn estimate_payload_bytes(
        path: &str,
        request_id: &str,
        traceparent: &str,
        request_json: &serde_json::Value,
        capture_mode: &str,
        primary_provider_id: &str,
        request_family: &str,
        decision_id: &str,
        target_id: &str,
    ) -> usize {
        let json_bytes = serde_json::to_vec(request_json)
            .map(|bytes| bytes.len())
            .unwrap_or_else(|_| estimate_json_len(request_json));
        path.len()
            + request_id.len()
            + traceparent.len()
            + capture_mode.len()
            + primary_provider_id.len()
            + request_family.len()
            + decision_id.len()
            + target_id.len()
            + json_bytes
    }
}

fn estimate_json_len(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Null => 4,
        serde_json::Value::Bool(_) => 5,
        serde_json::Value::Number(n) => n.to_string().len(),
        serde_json::Value::String(s) => s.len() + 2,
        serde_json::Value::Array(items) => items.iter().map(estimate_json_len).sum::<usize>() + 2,
        serde_json::Value::Object(map) => {
            map.iter()
                .map(|(k, v)| k.len() + 3 + estimate_json_len(v))
                .sum::<usize>()
                + 2
        }
    }
}

/// Metrics snapshot for load fixtures and operators.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShadowQueueStats {
    pub worker_count: usize,
    pub queued_items: usize,
    pub queued_bytes: usize,
    pub active_workers: usize,
    pub enqueued_total: u64,
    pub completed_total: u64,
    pub drops_item_limit: u64,
    pub drops_byte_limit: u64,
    pub drops_shutdown: u64,
    pub cancelled_in_flight: u64,
    pub peak_queued_items: usize,
    pub peak_queued_bytes: usize,
    pub peak_active_workers: usize,
    pub shutdown: bool,
}

/// Bounded shadow evaluation queue with a fixed worker pool.
pub struct ShadowEvaluationQueue {
    tx: mpsc::Sender<ShadowEvaluationJob>,
    /// Receiver held only until workers are spawned; then taken.
    rx: Mutex<Option<mpsc::Receiver<ShadowEvaluationJob>>>,
    queued_items: AtomicUsize,
    queued_bytes: AtomicUsize,
    active_workers: AtomicUsize,
    enqueued_total: AtomicU64,
    completed_total: AtomicU64,
    drops_item_limit: AtomicU64,
    drops_byte_limit: AtomicU64,
    drops_shutdown: AtomicU64,
    cancelled_in_flight: AtomicU64,
    peak_queued_items: AtomicUsize,
    peak_queued_bytes: AtomicUsize,
    peak_active_workers: AtomicUsize,
    workers_started: AtomicBool,
    shutdown_flag: AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    idle_notify: Notify,
    capacity: usize,
    max_bytes: usize,
    worker_count: usize,
}

impl ShadowEvaluationQueue {
    /// Create a queue with the production PERF-016 limits.
    pub fn with_defaults() -> Arc<Self> {
        Self::new(
            SHADOW_QUEUE_CAPACITY,
            SHADOW_QUEUE_MAX_BYTES,
            SHADOW_WORKER_COUNT,
        )
    }

    /// Create a queue with explicit limits (tests / load fixtures).
    pub fn new(capacity: usize, max_bytes: usize, worker_count: usize) -> Arc<Self> {
        let capacity = capacity.max(1);
        let worker_count = worker_count.max(1);
        let (tx, rx) = mpsc::channel(capacity);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let queue = Arc::new(Self {
            tx,
            rx: Mutex::new(Some(rx)),
            queued_items: AtomicUsize::new(0),
            queued_bytes: AtomicUsize::new(0),
            active_workers: AtomicUsize::new(0),
            enqueued_total: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            drops_item_limit: AtomicU64::new(0),
            drops_byte_limit: AtomicU64::new(0),
            drops_shutdown: AtomicU64::new(0),
            cancelled_in_flight: AtomicU64::new(0),
            peak_queued_items: AtomicUsize::new(0),
            peak_queued_bytes: AtomicUsize::new(0),
            peak_active_workers: AtomicUsize::new(0),
            workers_started: AtomicBool::new(false),
            shutdown_flag: AtomicBool::new(false),
            shutdown_tx,
            shutdown_rx,
            idle_notify: Notify::new(),
            capacity,
            max_bytes,
            worker_count,
        });
        queue.ensure_workers();
        queue
    }

    /// Process-wide shared queue used by the request pipeline.
    pub fn shared() -> Arc<Self> {
        if let Some(override_queue) = test_override_queue() {
            return override_queue;
        }
        static SHARED: OnceLock<Arc<ShadowEvaluationQueue>> = OnceLock::new();
        SHARED
            .get_or_init(ShadowEvaluationQueue::with_defaults)
            .clone()
    }

    /// Install a queue for integration tests; restores previous override on drop.
    #[doc(hidden)]
    pub fn install_for_test(queue: Arc<Self>) -> ShadowQueueTestGuard {
        let previous = {
            let mut slot = test_override_slot()
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (*slot).replace(queue)
        };
        ShadowQueueTestGuard { previous }
    }

    fn ensure_workers(self: &Arc<Self>) {
        if self
            .workers_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let rx = {
            let mut guard = self
                .rx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.take()
        };
        let Some(rx) = rx else {
            return;
        };
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        for worker_id in 0..self.worker_count {
            let queue = Arc::clone(self);
            let rx = Arc::clone(&rx);
            tokio::spawn(async move {
                queue.worker_loop(worker_id, rx).await;
            });
        }
    }

    /// Try to enqueue a job. Returns `Ok` on accept or `Err(reason)` on drop.
    pub fn try_enqueue(&self, job: ShadowEvaluationJob) -> Result<(), ShadowQueueDropReason> {
        if self.shutdown_flag.load(Ordering::Acquire) {
            self.drops_shutdown.fetch_add(1, Ordering::Relaxed);
            return Err(ShadowQueueDropReason::Shutdown);
        }

        let payload_bytes = job.payload_bytes;
        // Reserve item slot.
        let mut items = self.queued_items.load(Ordering::Acquire);
        loop {
            if items >= self.capacity {
                self.drops_item_limit.fetch_add(1, Ordering::Relaxed);
                return Err(ShadowQueueDropReason::ItemLimit);
            }
            match self.queued_items.compare_exchange_weak(
                items,
                items + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => items = observed,
            }
        }

        // Reserve byte budget.
        let mut bytes = self.queued_bytes.load(Ordering::Acquire);
        loop {
            if bytes.saturating_add(payload_bytes) > self.max_bytes {
                self.queued_items.fetch_sub(1, Ordering::AcqRel);
                self.drops_byte_limit.fetch_add(1, Ordering::Relaxed);
                return Err(ShadowQueueDropReason::ByteLimit);
            }
            match self.queued_bytes.compare_exchange_weak(
                bytes,
                bytes + payload_bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => bytes = observed,
            }
        }

        match self.tx.try_send(job) {
            Ok(()) => {
                self.enqueued_total.fetch_add(1, Ordering::Relaxed);
                self.record_peaks();
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(job)) => {
                self.release_reservation(job.payload_bytes);
                self.drops_item_limit.fetch_add(1, Ordering::Relaxed);
                Err(ShadowQueueDropReason::ItemLimit)
            }
            Err(mpsc::error::TrySendError::Closed(job)) => {
                self.release_reservation(job.payload_bytes);
                self.drops_shutdown.fetch_add(1, Ordering::Relaxed);
                Err(ShadowQueueDropReason::Shutdown)
            }
        }
    }

    fn release_reservation(&self, payload_bytes: usize) {
        self.queued_items.fetch_sub(1, Ordering::AcqRel);
        self.queued_bytes.fetch_sub(
            payload_bytes.min(self.queued_bytes.load(Ordering::Acquire)),
            Ordering::AcqRel,
        );
    }

    fn record_peaks(&self) {
        let items = self.queued_items.load(Ordering::Relaxed);
        let bytes = self.queued_bytes.load(Ordering::Relaxed);
        let active = self.active_workers.load(Ordering::Relaxed);
        self.peak_queued_items.fetch_max(items, Ordering::Relaxed);
        self.peak_queued_bytes.fetch_max(bytes, Ordering::Relaxed);
        self.peak_active_workers
            .fetch_max(active, Ordering::Relaxed);
    }

    async fn worker_loop(
        self: Arc<Self>,
        _worker_id: usize,
        rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ShadowEvaluationJob>>>,
    ) {
        let mut shutdown_rx = self.shutdown_rx.clone();
        loop {
            if self.shutdown_flag.load(Ordering::Acquire) {
                break;
            }
            let job = {
                let mut guard = rx.lock().await;
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            None
                        } else {
                            continue;
                        }
                    }
                    maybe_job = guard.recv() => maybe_job,
                }
            };
            let Some(job) = job else {
                break;
            };

            self.queued_items.fetch_sub(1, Ordering::AcqRel);
            self.queued_bytes.fetch_sub(
                job.payload_bytes
                    .min(self.queued_bytes.load(Ordering::Acquire)),
                Ordering::AcqRel,
            );

            if self.shutdown_flag.load(Ordering::Acquire) {
                self.drops_shutdown.fetch_add(1, Ordering::Relaxed);
                self.idle_notify.notify_waiters();
                continue;
            }

            let active = self.active_workers.fetch_add(1, Ordering::AcqRel) + 1;
            self.peak_active_workers
                .fetch_max(active, Ordering::Relaxed);

            let cancelled = run_shadow_job(job, &self.shutdown_flag).await;
            self.active_workers.fetch_sub(1, Ordering::AcqRel);
            if cancelled {
                self.cancelled_in_flight.fetch_add(1, Ordering::Relaxed);
            } else {
                self.completed_total.fetch_add(1, Ordering::Relaxed);
            }
            self.idle_notify.notify_waiters();
        }
    }

    /// Signal shutdown: reject new work and cancel workers.
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Release);
        let _ = self.shutdown_tx.send(true);
        // Drop queued jobs still sitting in the channel by closing the sender side
        // is not possible while `tx` lives; workers exit on shutdown watch and
        // remaining recv returns None after all senders drop. Force-drain via
        // try_recv is not exposed; count remaining reservations as shutdown drops.
        let remaining_items = self.queued_items.swap(0, Ordering::AcqRel);
        let _ = self.queued_bytes.swap(0, Ordering::AcqRel);
        if remaining_items > 0 {
            self.drops_shutdown
                .fetch_add(remaining_items as u64, Ordering::Relaxed);
        }
        self.idle_notify.notify_waiters();
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown_flag.load(Ordering::Acquire)
    }

    pub fn stats(&self) -> ShadowQueueStats {
        ShadowQueueStats {
            worker_count: self.worker_count,
            queued_items: self.queued_items.load(Ordering::Acquire),
            queued_bytes: self.queued_bytes.load(Ordering::Acquire),
            active_workers: self.active_workers.load(Ordering::Acquire),
            enqueued_total: self.enqueued_total.load(Ordering::Relaxed),
            completed_total: self.completed_total.load(Ordering::Relaxed),
            drops_item_limit: self.drops_item_limit.load(Ordering::Relaxed),
            drops_byte_limit: self.drops_byte_limit.load(Ordering::Relaxed),
            drops_shutdown: self.drops_shutdown.load(Ordering::Relaxed),
            cancelled_in_flight: self.cancelled_in_flight.load(Ordering::Relaxed),
            peak_queued_items: self.peak_queued_items.load(Ordering::Relaxed),
            peak_queued_bytes: self.peak_queued_bytes.load(Ordering::Relaxed),
            peak_active_workers: self.peak_active_workers.load(Ordering::Relaxed),
            shutdown: self.is_shutdown(),
        }
    }

    /// Wait until the queue reports no queued items and no active workers, or timeout.
    pub async fn wait_idle(&self, timeout: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let stats = self.stats();
            if stats.queued_items == 0 && stats.active_workers == 0 {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::select! {
                _ = self.idle_notify.notified() => {}
                _ = tokio::time::sleep_until(deadline) => {
                    let stats = self.stats();
                    return stats.queued_items == 0 && stats.active_workers == 0;
                }
            }
        }
    }
}

/// RAII guard restoring the previous test queue override.
pub struct ShadowQueueTestGuard {
    previous: Option<Arc<ShadowEvaluationQueue>>,
}

impl Drop for ShadowQueueTestGuard {
    fn drop(&mut self) {
        let mut slot = test_override_slot()
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = self.previous.take();
    }
}

fn test_override_slot() -> &'static RwLock<Option<Arc<ShadowEvaluationQueue>>> {
    static SLOT: OnceLock<RwLock<Option<Arc<ShadowEvaluationQueue>>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(None))
}

fn test_override_queue() -> Option<Arc<ShadowEvaluationQueue>> {
    test_override_slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

async fn run_shadow_job(job: ShadowEvaluationJob, shutdown_flag: &AtomicBool) -> bool {
    if shutdown_flag.load(Ordering::Acquire) {
        return true;
    }

    let ShadowEvaluationJob {
        client,
        target,
        path,
        request_id,
        traceparent,
        content_type,
        request_json,
        capture_mode,
        event_sink,
        primary_provider_id,
        request_family,
        decision_id,
        payload_bytes: _,
    } = job;

    let mut shadow_status: Option<u16> = None;
    if capture_mode == "full_payload" {
        if shutdown_flag.load(Ordering::Acquire) {
            return true;
        }
        let request_fut = super::execute_shadow_provider_request(
            client,
            target.clone(),
            path,
            request_id.clone(),
            traceparent.clone(),
            content_type,
            request_json,
        );
        // Cooperative cancel: poll shutdown between the await boundary by racing a watch.
        let result = tokio::select! {
            biased;
            _ = wait_until_shutdown(shutdown_flag) => {
                return true;
            }
            result = request_fut => result,
        };
        match result {
            Ok(status) => shadow_status = Some(status_code_u16(status)),
            Err(error) => {
                tracing::warn!(
                    request_id = %request_id,
                    shadow_target_id = %target.id,
                    error = %error,
                    "shadow evaluation request failed"
                );
            }
        }
    }

    if shutdown_flag.load(Ordering::Acquire) {
        return true;
    }

    if let Some(sink) = event_sink {
        let shadow_event = serde_json::json!({
            "event_id": format!("vdt_shadow_{decision_id}"),
            "event_type": "decision",
            "verdict": "shadow",
            "reason_code": "shadow_evaluation.recorded",
            "details": {
                "shadow_evaluation": {
                    "enabled": true,
                    "capture_mode": capture_mode,
                    "primary_provider": primary_provider_id,
                    "shadow_provider": target.id,
                    "request_family": request_family,
                    "decision_id": decision_id,
                    "payload_captured": capture_mode == "full_payload",
                    "shadow_status": shadow_status,
                }
            }
        });
        sink.enqueue_decision(&request_id, shadow_event.clone());
        // The primary decision for this request_id is already durable. Re-enqueue
        // the shadow evidence so the superseding-payload forward path delivers it
        // promptly instead of waiting behind unrelated WAL backlog.
        sink.enqueue_decision(&request_id, shadow_event);
    } else {
        tracing::warn!(
            request_id = %request_id,
            shadow_target_id = %target.id,
            "shadow evaluation completed without an event sink; shadow evidence was not recorded"
        );
    }
    false
}

async fn wait_until_shutdown(shutdown_flag: &AtomicBool) {
    while !shutdown_flag.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

fn status_code_u16(status: StatusCode) -> u16 {
    status.as_u16()
}

/// Test helper: build a metadata-only job with a synthetic byte weight.
#[doc(hidden)]
pub fn test_shadow_job_with_payload_bytes(
    payload_bytes: usize,
    request_id: impl Into<String>,
) -> ShadowEvaluationJob {
    let request_id = request_id.into();
    let padding = if payload_bytes > 64 {
        "x".repeat(payload_bytes.saturating_sub(64))
    } else {
        String::new()
    };
    let request_json = serde_json::json!({ "pad": padding });
    let measured = ShadowEvaluationJob::estimate_payload_bytes(
        "/v1/chat/completions",
        &request_id,
        "00-trace",
        &request_json,
        "metadata_only",
        "primary",
        "chat_completions",
        "shadow-test",
        "shadow-target",
    );
    ShadowEvaluationJob {
        client: reqwest::Client::new(),
        target: ProviderTarget {
            id: "shadow-target".to_string(),
            provider: "openai".to_string(),
            model: "gpt-test".to_string(),
            base_url: "http://127.0.0.1:9".to_string(),
            ..ProviderTarget::default()
        },
        path: "/v1/chat/completions".to_string(),
        request_id,
        traceparent: "00-trace".to_string(),
        content_type: Some(HeaderValue::from_static("application/json")),
        request_json,
        capture_mode: "metadata_only".to_string(),
        event_sink: None,
        primary_provider_id: "primary".to_string(),
        request_family: "chat_completions".to_string(),
        decision_id: "shadow-test".to_string(),
        // Use the caller-requested budget weight so load fixtures can force byte caps
        // without depending on serde size quirks; never under-count measured size.
        payload_bytes: payload_bytes.max(measured),
    }
}
