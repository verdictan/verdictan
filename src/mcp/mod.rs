// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! MCP (Model Context Protocol) support for Verdictan.
//!
//! Shared JSON-RPC handling lives in [`server`] and is reused by the current
//! transport layers.

pub mod audit;
pub mod local_context_runtime;
pub mod resources;
pub mod server;
pub mod tools;
pub mod transport;
