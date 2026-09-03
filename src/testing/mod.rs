// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Deterministic test helpers for unit tests.
//!
//! Consolidates mock-server, clock, and networking utilities for
//! `#[cfg(test)]` modules in `src/**` to exercise gateway and policy flows
//! without integration binaries.

#![allow(
    clippy::await_holding_lock,
    clippy::cloned_ref_to_slice_refs,
    clippy::collapsible_match,
    clippy::disallowed_methods,
    clippy::expect_fun_call,
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used
)]

pub(crate) mod cli_harness;
pub(crate) mod deterministic_net;
pub mod gateway_jwt;
pub mod oauth_mock_api;
pub(crate) mod test_server;
