// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

pub mod custom_api;
pub mod http;
pub mod mcp;
pub mod websocket;

#[allow(dead_code)]
pub trait VerdictanNetworkAdapterRuntime: super::VerdictanRuntime {
    fn adapter_id(&self) -> &'static str;
    fn validate_endpoint(&self, endpoint: &str) -> Result<(), CliError>;
    fn serialize_request(&self, request: &Value) -> Result<Value, CliError>;
    fn execute_network_call(&self, config: &Value, request: &Value) -> Result<Value, CliError>;
    fn parse_network_response(&self, response: &Value) -> Result<Value, CliError>;
}
