// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;

pub mod ai21;
pub mod aimlapi;
pub mod alibaba;
pub mod anthropic;
pub mod aws_bedrock;
pub mod azure;
pub mod cerebras;
pub mod cloudera;
pub mod cloudflare_ai;
pub mod cloudflare_gateway;
pub mod cohere;
pub mod cometapi;
pub mod databricks;
pub mod deepseek;
pub mod elevenlabs;
pub mod envoy;
pub mod f5;
pub mod fal;
pub mod fireworks;
pub mod github;
pub mod google;
pub mod groq;
pub mod helicone;
pub mod huggingface;
pub mod hyperbolic;
pub mod ibm_bam;
pub mod jfrog;
pub mod litellm;
pub mod llama_cpp;
pub mod llamaapi;
pub mod llamafile;
pub mod localai;
pub mod mistral;
pub mod modelslab;
pub mod nscale;
pub mod ollama;
pub mod openai;
pub mod openclaw;
pub mod openllm;
pub mod openrouter;
pub mod perplexity;
pub mod quiverai;
pub mod replicate;
pub mod sagemaker;
pub mod snowflake;
pub mod text_generation_webui;
pub mod togetherai;
pub mod truefoundry;
pub mod vercel;
pub mod vertex;
pub mod vllm;
pub mod voyage;
pub mod watsonx;
pub mod xai;

#[allow(dead_code)]
pub trait VerdictanUpstreamRuntime: super::VerdictanRuntime {
    fn provider_kind(&self) -> &'static str;
    fn validate_endpoint_url(&self, base_url: &str) -> Result<(), CliError>;
    fn normalize_upstream_response(&self, response: &Value) -> Result<Value, CliError>;
}
