// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

pub mod custom_script;
pub mod docker;
pub mod echo;
pub mod go;
pub mod manual_input;
pub mod python;
pub mod ruby;
pub mod transformers;

#[allow(dead_code)]
pub trait VerdictanLocalRuntime: super::VerdictanRuntime {
    fn resolve_binary(&self, config: &Value) -> Result<String, CliError>;
    fn validate_local_inputs(&self, config: &Value, request: &Value) -> Result<(), CliError>;
    fn execute_local(&self, config: &Value, request: &Value) -> Result<Value, CliError>;
    fn parse_local_output(&self, output: &str) -> Result<Value, CliError>;
}
