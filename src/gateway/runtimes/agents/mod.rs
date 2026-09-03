// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

pub mod bedrock_agents;
pub mod chatkit;
pub mod claude_agent_sdk;
pub mod codex_sdk;
pub mod openai_agents;
pub mod opencode_sdk;

#[allow(dead_code)]
pub trait VerdictanAgentRuntime: super::VerdictanRuntime {
    fn initialize_agent(&self, config: &Value) -> Result<Value, CliError>;
    fn execute_agent_call(
        &self,
        config: &Value,
        state: &Value,
        request: &Value,
    ) -> Result<Value, CliError>;
    fn stream_agent_events(&self, state: &Value) -> Result<Vec<Value>, CliError>;
    fn finalize_agent_state(&self, state: &Value) -> Result<Value, CliError>;
}
