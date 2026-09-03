// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

pub mod browser;
pub mod sequence;
pub mod simulated_user;
pub mod slack_feedback;

#[allow(dead_code)]
pub trait VerdictanInteractiveRuntime: super::VerdictanRuntime {
    fn initialize_session(&self, config: &Value) -> Result<Value, CliError>;
    fn execute_step(
        &self,
        config: &Value,
        session: &Value,
        request: &Value,
    ) -> Result<Value, CliError>;
    fn capture_state(&self, session: &Value) -> Result<Value, CliError>;
    fn finalize_session(&self, session: &Value) -> Result<Value, CliError>;
}
