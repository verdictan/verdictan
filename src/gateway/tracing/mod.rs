// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

// cli/src/gateway/tracing/mod.rs
//
// Workflow-lineage-aware tracing for the gateway runtime (Phase 5).
//
// Provides OTEL-compatible span emission for the five lifecycle events that
// carry workflow context: outbound provider requests, tool/function calls,
// cache lookups/writes, approval events, and routing decisions.
//
// Design constraints:
//   - No DB writes: spans are forwarded via the existing OTEL export pipeline.
//   - Privacy: message content is scrubbed; only structural metadata is emitted.
//   - Additive: does not break or replace the existing proxy_phase_span flow.

pub mod workflow_spans;
