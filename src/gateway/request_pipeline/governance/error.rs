// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Governance pipeline error types.

use super::stages::GovernanceStage;

/// Failure produced by a governance stage or family adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceError {
    pub stage: Option<GovernanceStage>,
    pub code: String,
    pub message: String,
}

impl GovernanceError {
    pub fn at_stage(
        stage: GovernanceStage,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            stage: Some(stage),
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn adapter(message: impl Into<String>) -> Self {
        Self {
            stage: None,
            code: "governance.adapter".into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.stage {
            Some(stage) => write!(f, "{}: {} ({})", stage.as_str(), self.code, self.message),
            None => write!(f, "{} ({})", self.code, self.message),
        }
    }
}

impl std::error::Error for GovernanceError {}

pub type GovernanceResult<T> = Result<T, GovernanceError>;
