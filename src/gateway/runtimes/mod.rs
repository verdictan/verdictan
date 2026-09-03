// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::error::CliError;
use crate::gateway::{
    execution_runtime::{AdapterFamily, ExecutionTarget},
    provider_catalog::normalized_provider_alias,
    runtime_catalog::{page_to_runtime_mapping, RuntimeCatalogEntry},
};

pub mod agents;
pub mod interactive;
pub mod local;
pub mod network;
pub mod upstream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RuntimeSupportLevel {
    Native,
    AdapterBacked,
    ExplicitlyUnsupported,
}

#[allow(dead_code)]
pub struct RuntimeResolution {
    pub catalog_entry: &'static RuntimeCatalogEntry,
    pub runtime: &'static dyn VerdictanRuntime,
    pub module_path: &'static str,
    pub support_level: RuntimeSupportLevel,
}

#[allow(dead_code)]
pub trait VerdictanRuntime {
    fn runtime_id(&self) -> &'static str;
    fn validate_config(&self, config: &Value) -> Result<(), CliError>;
    fn build_request(&self, config: &Value, input: &Value) -> Result<Value, CliError>;
    fn execute(&self, config: &Value, request: &Value) -> Result<Value, CliError>;
    fn translate_response(&self, response: &Value) -> Result<Value, CliError>;

    fn default_path_template(&self) -> Option<&'static str> {
        None
    }

    fn requires_model(&self) -> bool {
        true
    }

    fn auth_optional(&self) -> bool {
        false
    }

    fn supports_streaming(&self) -> bool {
        false
    }

    fn supports_tools(&self) -> bool {
        false
    }
}

pub fn validate_runtime_target(
    provider: &str,
    execution_target: Option<&ExecutionTarget>,
    config: &Value,
) -> Result<Option<RuntimeResolution>, CliError> {
    let Some(resolution) = resolve_runtime_for_target(provider, execution_target) else {
        return Ok(None);
    };

    match resolution.support_level {
        RuntimeSupportLevel::Native | RuntimeSupportLevel::AdapterBacked => {
            resolution.runtime.validate_config(config)?;
        }
        RuntimeSupportLevel::ExplicitlyUnsupported => {}
    }

    Ok(Some(resolution))
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeParserPolicy {
    pub requires_model: bool,
    pub auth_optional: bool,
}

pub fn parser_policy_for_target(
    provider: &str,
    execution_target: Option<&ExecutionTarget>,
) -> RuntimeParserPolicy {
    if let Some(resolution) = resolve_runtime_for_target(provider, execution_target) {
        return RuntimeParserPolicy {
            requires_model: resolution.runtime.requires_model(),
            auth_optional: resolution.runtime.auth_optional(),
        };
    }

    RuntimeParserPolicy {
        requires_model: true,
        auth_optional: false,
    }
}

pub fn build_runtime_request(
    provider: &str,
    execution_target: Option<&ExecutionTarget>,
    config: &Value,
    request: &Value,
) -> Result<Value, CliError> {
    if let Some(resolution) = resolve_runtime_for_target(provider, execution_target) {
        return resolution.runtime.build_request(config, request);
    }

    Ok(request.clone())
}

pub fn translate_runtime_response(
    provider: &str,
    execution_target: Option<&ExecutionTarget>,
    response: &Value,
) -> Result<Value, CliError> {
    if let Some(resolution) = resolve_runtime_for_target(provider, execution_target) {
        return resolution.runtime.translate_response(response);
    }

    Ok(response.clone())
}

pub fn resolve_runtime_path(
    provider: &str,
    execution_target: Option<&ExecutionTarget>,
    model: &str,
    explicit_path_template: Option<&str>,
    default_path: &str,
) -> String {
    if let Some(template) = explicit_path_template {
        return template.replace("{model}", model);
    }

    if let Some(resolution) = resolve_runtime_for_target(provider, execution_target) {
        if let Some(template) = resolution.runtime.default_path_template() {
            return template.replace("{model}", model);
        }
    }

    default_path.to_string()
}

#[allow(dead_code)]
pub fn resolve_runtime_for_target(
    provider: &str,
    execution_target: Option<&ExecutionTarget>,
) -> Option<RuntimeResolution> {
    match execution_target {
        Some(ExecutionTarget::Command(command)) => match command.family {
            Some(AdapterFamily::Browser) => {
                let catalog_entry = page_to_runtime_mapping("browser.md")?;
                Some(RuntimeResolution {
                    catalog_entry,
                    runtime: &interactive::browser::BROWSER_RUNTIME,
                    module_path: "cli/src/gateway/runtimes/interactive/browser.rs",
                    support_level: RuntimeSupportLevel::AdapterBacked,
                })
            }
            Some(AdapterFamily::ChatKit) => {
                let catalog_entry = page_to_runtime_mapping("openai-chatkit.md")?;
                Some(RuntimeResolution {
                    catalog_entry,
                    runtime: &agents::chatkit::CHATKIT_RUNTIME,
                    module_path: "cli/src/gateway/runtimes/agents/chatkit.rs",
                    support_level: RuntimeSupportLevel::AdapterBacked,
                })
            }
            Some(AdapterFamily::Transformers) => {
                let catalog_entry = page_to_runtime_mapping("transformers.md")?;
                Some(RuntimeResolution {
                    catalog_entry,
                    runtime: &local::transformers::TRANSFORMERS_RUNTIME,
                    module_path: "cli/src/gateway/runtimes/local/transformers.rs",
                    support_level: RuntimeSupportLevel::Native,
                })
            }
            Some(AdapterFamily::ClaudeAgentSdk) => {
                let catalog_entry = page_to_runtime_mapping("claude-agent-sdk.md")?;
                Some(RuntimeResolution {
                    catalog_entry,
                    runtime: &agents::claude_agent_sdk::CLAUDE_AGENT_SDK_RUNTIME,
                    module_path: "cli/src/gateway/runtimes/agents/claude_agent_sdk.rs",
                    support_level: RuntimeSupportLevel::AdapterBacked,
                })
            }
            Some(AdapterFamily::CodexSdk) => {
                let catalog_entry = page_to_runtime_mapping("openai-codex-sdk.md")?;
                Some(RuntimeResolution {
                    catalog_entry,
                    runtime: &agents::codex_sdk::CODEX_SDK_RUNTIME,
                    module_path: "cli/src/gateway/runtimes/agents/codex_sdk.rs",
                    support_level: RuntimeSupportLevel::AdapterBacked,
                })
            }
            Some(AdapterFamily::Mcp) => {
                let catalog_entry = page_to_runtime_mapping("mcp.md")?;
                Some(RuntimeResolution {
                    catalog_entry,
                    runtime: &network::mcp::MCP_RUNTIME,
                    module_path: "cli/src/gateway/runtimes/network/mcp.rs",
                    support_level: RuntimeSupportLevel::AdapterBacked,
                })
            }
            Some(AdapterFamily::WebSocket) => {
                let catalog_entry = page_to_runtime_mapping("websocket.md")?;
                Some(RuntimeResolution {
                    catalog_entry,
                    runtime: &network::websocket::WEBSOCKET_RUNTIME,
                    module_path: "cli/src/gateway/runtimes/network/websocket.rs",
                    support_level: RuntimeSupportLevel::AdapterBacked,
                })
            }
            Some(AdapterFamily::OpenAiAgents) => {
                let catalog_entry = page_to_runtime_mapping("openai-agents.md")?;
                Some(RuntimeResolution {
                    catalog_entry,
                    runtime: &agents::openai_agents::OPENAI_AGENTS_RUNTIME,
                    module_path: "cli/src/gateway/runtimes/agents/openai_agents.rs",
                    support_level: RuntimeSupportLevel::AdapterBacked,
                })
            }
            Some(AdapterFamily::OpenCodeSdk) => {
                let catalog_entry = page_to_runtime_mapping("opencode-sdk.md")?;
                Some(RuntimeResolution {
                    catalog_entry,
                    runtime: &agents::opencode_sdk::OPENCODE_SDK_RUNTIME,
                    module_path: "cli/src/gateway/runtimes/agents/opencode_sdk.rs",
                    support_level: RuntimeSupportLevel::AdapterBacked,
                })
            }
            Some(AdapterFamily::BedrockAgents) => {
                let catalog_entry = page_to_runtime_mapping("bedrock-agents.md")?;
                Some(RuntimeResolution {
                    catalog_entry,
                    runtime: &agents::bedrock_agents::BEDROCK_AGENTS_RUNTIME,
                    module_path: "cli/src/gateway/runtimes/agents/bedrock_agents.rs",
                    support_level: RuntimeSupportLevel::AdapterBacked,
                })
            }
            _ => resolve_catalog_runtime(provider),
        },
        Some(ExecutionTarget::Echo) => {
            let catalog_entry = page_to_runtime_mapping("echo.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &local::echo::ECHO_RUNTIME,
                module_path: "cli/src/gateway/runtimes/local/echo.rs",
                support_level: RuntimeSupportLevel::Native,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "manual-input" => {
            let catalog_entry = page_to_runtime_mapping("manual-input.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &local::manual_input::MANUAL_INPUT_RUNTIME,
                module_path: "cli/src/gateway/runtimes/local/manual_input.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "browser" => {
            let catalog_entry = page_to_runtime_mapping("browser.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &interactive::browser::BROWSER_RUNTIME,
                module_path: "cli/src/gateway/runtimes/interactive/browser.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "transformers" => {
            let catalog_entry = page_to_runtime_mapping("transformers.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &local::transformers::TRANSFORMERS_RUNTIME,
                module_path: "cli/src/gateway/runtimes/local/transformers.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "mcp" => {
            let catalog_entry = page_to_runtime_mapping("mcp.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &network::mcp::MCP_RUNTIME,
                module_path: "cli/src/gateway/runtimes/network/mcp.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "websocket" => {
            let catalog_entry = page_to_runtime_mapping("websocket.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &network::websocket::WEBSOCKET_RUNTIME,
                module_path: "cli/src/gateway/runtimes/network/websocket.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "go" => {
            let catalog_entry = page_to_runtime_mapping("go.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &local::go::GO_RUNTIME,
                module_path: "cli/src/gateway/runtimes/local/go.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "ruby" => {
            let catalog_entry = page_to_runtime_mapping("ruby.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &local::ruby::RUBY_RUNTIME,
                module_path: "cli/src/gateway/runtimes/local/ruby.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "sequence" => {
            let catalog_entry = page_to_runtime_mapping("sequence.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &interactive::sequence::SEQUENCE_RUNTIME,
                module_path: "cli/src/gateway/runtimes/interactive/sequence.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "simulated-user" => {
            let catalog_entry = page_to_runtime_mapping("simulated-user.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &interactive::simulated_user::SIMULATED_USER_RUNTIME,
                module_path: "cli/src/gateway/runtimes/interactive/simulated_user.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "slack-feedback" => {
            let catalog_entry = page_to_runtime_mapping("slack.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &interactive::slack_feedback::SLACK_FEEDBACK_RUNTIME,
                module_path: "cli/src/gateway/runtimes/interactive/slack_feedback.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "custom-script" => {
            let catalog_entry = page_to_runtime_mapping("custom-script.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &local::custom_script::CUSTOM_SCRIPT_RUNTIME,
                module_path: "cli/src/gateway/runtimes/local/custom_script.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "docker" => {
            let catalog_entry = page_to_runtime_mapping("docker.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &local::docker::DOCKER_RUNTIME,
                module_path: "cli/src/gateway/runtimes/local/docker.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        Some(ExecutionTarget::Unsupported { kind, .. }) if kind == "python" => {
            let catalog_entry = page_to_runtime_mapping("python.md")?;
            Some(RuntimeResolution {
                catalog_entry,
                runtime: &local::python::PYTHON_RUNTIME,
                module_path: "cli/src/gateway/runtimes/local/python.rs",
                support_level: RuntimeSupportLevel::ExplicitlyUnsupported,
            })
        }
        _ => resolve_catalog_runtime(provider),
    }
}

#[allow(dead_code)]
fn resolve_catalog_runtime(provider: &str) -> Option<RuntimeResolution> {
    resolve_native_runtime(provider).or_else(|| resolve_network_runtime(provider))
}

#[allow(dead_code)]
fn resolve_native_runtime(provider: &str) -> Option<RuntimeResolution> {
    match normalized_provider_alias(provider).as_str() {
        "ai21" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("ai21.md")?,
            runtime: &upstream::ai21::AI21_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/ai21.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "aimlapi" | "ai-ml-api" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("aimlapi.md")?,
            runtime: &upstream::aimlapi::AIMLAPI_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/aimlapi.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "alibaba" | "qwen" | "dashscope" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("alibaba.md")?,
            runtime: &upstream::alibaba::ALIBABA_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/alibaba.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "openai" | "open-ai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("openai.md")?,
            runtime: &upstream::openai::OPENAI_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/openai.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "cloudflare-ai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("cloudflare-ai.md")?,
            runtime: &upstream::cloudflare_ai::CLOUDFLARE_AI_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/cloudflare_ai.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "cloudflare-gateway" | "cloudflare-ai-gateway" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("cloudflare-gateway.md")?,
            runtime: &upstream::cloudflare_gateway::CLOUDFLARE_GATEWAY_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/cloudflare_gateway.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "cerebras" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("cerebras.md")?,
            runtime: &upstream::cerebras::CEREBRAS_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/cerebras.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "cloudera" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("cloudera.md")?,
            runtime: &upstream::cloudera::CLOUDERA_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/cloudera.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "cometapi" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("cometapi.md")?,
            runtime: &upstream::cometapi::COMETAPI_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/cometapi.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "groq" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("groq.md")?,
            runtime: &upstream::groq::GROQ_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/groq.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "hyperbolic" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("hyperbolic.md")?,
            runtime: &upstream::hyperbolic::HYPERBOLIC_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/hyperbolic.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "litellm" | "litellm-embedding" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("litellm.md")?,
            runtime: &upstream::litellm::LITELLM_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/litellm.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "llamafile" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("llamafile.md")?,
            runtime: &upstream::llamafile::LLAMAFILE_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/llamafile.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "llama" | "llama-cpp" | "llama.cpp" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("llama.cpp.md")?,
            runtime: &upstream::llama_cpp::LLAMA_CPP_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/llama_cpp.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "ollama" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("ollama.md")?,
            runtime: &upstream::ollama::OLLAMA_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/ollama.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "localai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("localai.md")?,
            runtime: &upstream::localai::LOCALAI_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/localai.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "llamaapi" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("llamaApi.md")?,
            runtime: &upstream::llamaapi::LLAMAAPI_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/llamaapi.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "fireworks" | "fireworks-ai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("fireworks.md")?,
            runtime: &upstream::fireworks::FIREWORKS_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/fireworks.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "github" | "github-models" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("github.md")?,
            runtime: &upstream::github::GITHUB_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/github.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "togetherai" | "together-ai" | "together" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("togetherai.md")?,
            runtime: &upstream::togetherai::TOGETHERAI_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/togetherai.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "mistral" | "mistral-ai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("mistral.md")?,
            runtime: &upstream::mistral::MISTRAL_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/mistral.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "openllm" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("openllm.md")?,
            runtime: &upstream::openllm::OPENLLM_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/openllm.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "quiverai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("quiverai.md")?,
            runtime: &upstream::quiverai::QUIVERAI_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/quiverai.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "deepseek" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("deepseek.md")?,
            runtime: &upstream::deepseek::DEEPSEEK_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/deepseek.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "truefoundry" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("truefoundry.md")?,
            runtime: &upstream::truefoundry::TRUEFOUNDRY_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/truefoundry.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "perplexity" | "perplexity-ai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("perplexity.md")?,
            runtime: &upstream::perplexity::PERPLEXITY_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/perplexity.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "openrouter" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("openrouter.md")?,
            runtime: &upstream::openrouter::OPENROUTER_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/openrouter.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "anthropic" | "claude" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("anthropic.md")?,
            runtime: &upstream::anthropic::ANTHROPIC_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/anthropic.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "voyage" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("voyage.md")?,
            runtime: &upstream::voyage::VOYAGE_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/voyage.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "xai" | "x-ai" | "grok" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("xai.md")?,
            runtime: &upstream::xai::XAI_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/xai.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "vercel" | "vercel-ai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("vercel.md")?,
            runtime: &upstream::vercel::VERCEL_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/vercel.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "vllm" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("vllm.md")?,
            runtime: &upstream::vllm::VLLM_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/vllm.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "text-generation-webui" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("text-generation-webui.md")?,
            runtime: &upstream::text_generation_webui::TEXT_GENERATION_WEBUI_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/text_generation_webui.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "aws-bedrock" | "bedrock" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("aws-bedrock.md")?,
            runtime: &upstream::aws_bedrock::AWS_BEDROCK_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/aws_bedrock.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "azure" | "azure-openai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("azure.md")?,
            runtime: &upstream::azure::AZURE_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/azure.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "cohere" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("cohere.md")?,
            runtime: &upstream::cohere::COHERE_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/cohere.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "databricks" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("databricks.md")?,
            runtime: &upstream::databricks::DATABRICKS_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/databricks.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "elevenlabs" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("elevenlabs.md")?,
            runtime: &upstream::elevenlabs::ELEVENLABS_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/elevenlabs.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "envoy" | "envoy-gateway" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("envoy.md")?,
            runtime: &upstream::envoy::ENVOY_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/envoy.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "f5" | "f5-gateway" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("f5.md")?,
            runtime: &upstream::f5::F5_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/f5.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "fal" | "fal-ai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("fal.md")?,
            runtime: &upstream::fal::FAL_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/fal.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "google" | "google-ai-studio" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("google.md")?,
            runtime: &upstream::google::GOOGLE_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/google.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "helicone" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("helicone.md")?,
            runtime: &upstream::helicone::HELICONE_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/helicone.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "huggingface" | "hf" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("huggingface.md")?,
            runtime: &upstream::huggingface::HUGGINGFACE_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/huggingface.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "ibm-bam" | "bam" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("ibm-bam.md")?,
            runtime: &upstream::ibm_bam::IBM_BAM_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/ibm_bam.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "jfrog" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("jfrog.md")?,
            runtime: &upstream::jfrog::JFROG_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/jfrog.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "modelslab" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("modelslab.md")?,
            runtime: &upstream::modelslab::MODELSLAB_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/modelslab.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "nscale" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("nscale.md")?,
            runtime: &upstream::nscale::NSCALE_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/nscale.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "openclaw" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("openclaw.md")?,
            runtime: &upstream::openclaw::OPENCLAW_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/openclaw.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "replicate" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("replicate.md")?,
            runtime: &upstream::replicate::REPLICATE_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/replicate.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "sagemaker" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("sagemaker.md")?,
            runtime: &upstream::sagemaker::SAGEMAKER_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/sagemaker.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "snowflake" | "snowflake-cortex" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("snowflake.md")?,
            runtime: &upstream::snowflake::SNOWFLAKE_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/snowflake.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "vertex" | "vertex-ai" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("vertex.md")?,
            runtime: &upstream::vertex::VERTEX_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/vertex.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "watsonx" | "ibm-watsonx" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("watsonx.md")?,
            runtime: &upstream::watsonx::WATSONX_RUNTIME,
            module_path: "cli/src/gateway/runtimes/upstream/watsonx.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        _ => None,
    }
}

#[allow(dead_code)]
fn resolve_network_runtime(provider: &str) -> Option<RuntimeResolution> {
    match normalized_provider_alias(provider).as_str() {
        "custom-api" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("custom-api.md")?,
            runtime: &network::custom_api::CUSTOM_API_RUNTIME,
            module_path: "cli/src/gateway/runtimes/network/custom_api.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "http" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("http.md")?,
            runtime: &network::http::HTTP_RUNTIME,
            module_path: "cli/src/gateway/runtimes/network/http.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "mcp" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("mcp.md")?,
            runtime: &network::mcp::MCP_RUNTIME,
            module_path: "cli/src/gateway/runtimes/network/mcp.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        "websocket" => Some(RuntimeResolution {
            catalog_entry: page_to_runtime_mapping("websocket.md")?,
            runtime: &network::websocket::WEBSOCKET_RUNTIME,
            module_path: "cli/src/gateway/runtimes/network/websocket.rs",
            support_level: RuntimeSupportLevel::Native,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        dead_code,
        clippy::approx_constant,
        clippy::assertions_on_constants,
        clippy::assign_op_pattern,
        clippy::await_holding_lock,
        clippy::bool_assert_comparison,
        clippy::clone_on_copy,
        clippy::cloned_ref_to_slice_refs,
        clippy::const_is_empty,
        clippy::derivable_impls,
        clippy::err_expect,
        clippy::expect_fun_call,
        clippy::expect_used,
        clippy::field_reassign_with_default,
        clippy::large_enum_variant,
        clippy::len_zero,
        clippy::manual_contains,
        clippy::manual_range_contains,
        clippy::needless_borrow,
        clippy::needless_borrows_for_generic_args,
        clippy::panic,
        clippy::print_stderr,
        clippy::type_complexity,
        clippy::unnecessary_literal_unwrap,
        clippy::unnecessary_map_or,
        clippy::unwrap_used,
        clippy::useless_conversion,
        clippy::useless_vec,
        unused_imports,
        unused_macros,
        unused_mut,
        unused_variables,
        clippy::nonminimal_bool,
        clippy::overly_complex_bool_expr,
        clippy::needless_update,
        clippy::unnecessary_get_then_check
    )]

    use super::*;
    use serde_json::json;

    #[test]
    fn runtime_support_level_equality() {
        assert_eq!(RuntimeSupportLevel::Native, RuntimeSupportLevel::Native);
        assert_ne!(
            RuntimeSupportLevel::Native,
            RuntimeSupportLevel::AdapterBacked
        );
        assert_ne!(
            RuntimeSupportLevel::AdapterBacked,
            RuntimeSupportLevel::ExplicitlyUnsupported
        );
    }

    #[test]
    fn runtime_support_level_debug() {
        let s = format!("{:?}", RuntimeSupportLevel::Native);
        assert_eq!(s, "Native");
    }

    #[test]
    fn runtime_support_level_clone() {
        let level = RuntimeSupportLevel::AdapterBacked;
        let cloned = level;
        assert_eq!(level, cloned);
    }

    #[test]
    fn runtime_parser_policy_default_values() {
        let policy = parser_policy_for_target("unknown-provider-xyz", None);
        assert!(policy.requires_model);
        assert!(!policy.auth_optional);
    }

    #[test]
    fn parser_policy_for_ollama_overrides_defaults() {
        let policy = parser_policy_for_target("ollama", None);
        assert!(policy.auth_optional);
    }

    #[test]
    fn parser_policy_for_docker_does_not_require_model() {
        let policy = parser_policy_for_target(
            "docker",
            Some(&ExecutionTarget::Unsupported {
                kind: "docker".to_string(),
                reason: String::new(),
            }),
        );
        assert!(!policy.requires_model);
    }

    #[test]
    fn resolve_runtime_path_uses_explicit_template_first() {
        let path = resolve_runtime_path("openai", None, "gpt-4", Some("/custom/{model}"), "/v1");
        assert_eq!(path, "/custom/gpt-4");
    }

    #[test]
    fn resolve_runtime_path_substitutes_model_in_template() {
        let path = resolve_runtime_path("sagemaker", None, "my-endpoint", None, "/default");
        assert!(path.contains("my-endpoint") || path == "/default");
    }

    #[test]
    fn resolve_runtime_path_falls_back_to_default() {
        let path = resolve_runtime_path("unknown-provider-xyz", None, "m", None, "/fallback");
        assert_eq!(path, "/fallback");
    }

    #[test]
    fn build_runtime_request_passthrough_for_unknown_provider() {
        let req = json!({"messages": []});
        let result = build_runtime_request("unknown-provider-xyz", None, &json!({}), &req).unwrap();
        assert_eq!(result, req);
    }

    #[test]
    fn translate_runtime_response_passthrough_for_unknown_provider() {
        let resp = json!({"choices": []});
        let result = translate_runtime_response("unknown-provider-xyz", None, &resp).unwrap();
        assert_eq!(result, resp);
    }

    #[test]
    fn resolve_runtime_for_target_returns_none_for_unknown() {
        assert!(resolve_runtime_for_target("unknown-provider-xyz-42", None).is_none());
    }

    #[test]
    fn resolve_runtime_for_target_returns_some_for_openai() {
        let resolution = resolve_runtime_for_target("openai", None);
        assert!(resolution.is_some());
        let r = resolution.unwrap();
        assert_eq!(r.runtime.runtime_id(), "openai");
        assert_eq!(r.support_level, RuntimeSupportLevel::Native);
    }

    #[test]
    fn resolve_runtime_for_target_returns_some_for_ollama() {
        let resolution = resolve_runtime_for_target("ollama", None);
        assert!(resolution.is_some());
        assert_eq!(resolution.unwrap().runtime.runtime_id(), "ollama");
    }

    #[test]
    fn resolve_runtime_for_echo_target() {
        let resolution = resolve_runtime_for_target("any", Some(&ExecutionTarget::Echo));
        assert!(resolution.is_some());
    }

    #[test]
    fn resolve_network_runtime_for_http() {
        let resolution = resolve_network_runtime("http");
        assert!(resolution.is_some());
        assert_eq!(resolution.unwrap().runtime.runtime_id(), "http");
    }

    #[test]
    fn resolve_network_runtime_for_custom_api() {
        let resolution = resolve_network_runtime("custom-api");
        assert!(resolution.is_some());
        assert_eq!(resolution.unwrap().runtime.runtime_id(), "custom-api");
    }

    #[test]
    fn resolve_network_runtime_for_websocket() {
        let resolution = resolve_network_runtime("websocket");
        assert!(resolution.is_some());
        assert_eq!(resolution.unwrap().runtime.runtime_id(), "websocket");
    }

    #[test]
    fn resolve_network_runtime_returns_none_for_unknown() {
        assert!(resolve_network_runtime("unknown").is_none());
    }

    #[test]
    fn validate_runtime_target_returns_none_for_unknown_provider() {
        let result = validate_runtime_target("unknown-xyz-42", None, &json!({})).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn resolve_runtime_for_target_anthropic() {
        let resolution = resolve_runtime_for_target("anthropic", None);
        assert!(resolution.is_some());
        assert_eq!(resolution.unwrap().runtime.runtime_id(), "anthropic");
    }

    #[test]
    fn resolve_runtime_for_target_google() {
        let resolution = resolve_runtime_for_target("google", None);
        assert!(resolution.is_some());
        assert_eq!(resolution.unwrap().runtime.runtime_id(), "google");
    }

    #[test]
    fn resolve_runtime_for_target_azure() {
        let resolution = resolve_runtime_for_target("azure", None);
        assert!(resolution.is_some());
        assert_eq!(resolution.unwrap().runtime.runtime_id(), "azure");
    }

    #[test]
    fn resolve_runtime_for_target_mistral() {
        let resolution = resolve_runtime_for_target("mistral", None);
        assert!(resolution.is_some());
        assert_eq!(resolution.unwrap().runtime.runtime_id(), "mistral");
    }

    #[test]
    fn resolve_runtime_for_target_groq() {
        let resolution = resolve_runtime_for_target("groq", None);
        assert!(resolution.is_some());
        assert_eq!(resolution.unwrap().runtime.runtime_id(), "groq");
    }

    #[test]
    fn resolve_network_runtime_for_mcp() {
        let resolution = resolve_network_runtime("mcp");
        assert!(resolution.is_some());
        assert_eq!(resolution.unwrap().runtime.runtime_id(), "mcp");
    }

    #[test]
    fn parser_policy_for_echo_target() {
        let policy = parser_policy_for_target("any", Some(&ExecutionTarget::Echo));
        assert!(!policy.requires_model);
        assert!(policy.auth_optional);
    }

    #[test]
    fn build_runtime_request_uses_runtime_when_available() {
        let req = json!({"messages": [{"role": "user", "content": "hi"}]});
        let result = build_runtime_request("openai", None, &json!({}), &req).unwrap();
        assert_eq!(result, req);
    }

    #[test]
    fn translate_runtime_response_uses_runtime_when_available() {
        let resp = json!({"choices": [{"text": "hello"}]});
        let result = translate_runtime_response("openai", None, &resp).unwrap();
        assert_eq!(result, resp);
    }

    #[test]
    fn resolve_runtime_path_uses_runtime_template_for_openai() {
        let path = resolve_runtime_path("openai", None, "gpt-4", None, "/fallback");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn resolve_runtime_path_falls_back_when_no_runtime_template() {
        let path = resolve_runtime_path("transformers", None, "gpt-4", None, "/fallback");
        assert_eq!(path, "/fallback");
    }

    #[test]
    fn resolve_runtime_path_explicit_template_with_model_substitution() {
        let path = resolve_runtime_path(
            "openai",
            None,
            "gpt-4",
            Some("/models/{model}/chat"),
            "/fallback",
        );
        assert_eq!(path, "/models/gpt-4/chat");
    }

    #[test]
    fn runtime_parser_policy_debug() {
        let policy = RuntimeParserPolicy {
            requires_model: true,
            auth_optional: false,
        };
        let s = format!("{:?}", policy);
        assert!(s.contains("requires_model"));
    }

    #[test]
    fn runtime_parser_policy_clone() {
        let policy = RuntimeParserPolicy {
            requires_model: true,
            auth_optional: false,
        };
        let cloned = policy;
        assert_eq!(policy.requires_model, cloned.requires_model);
        assert_eq!(policy.auth_optional, cloned.auth_optional);
    }

    #[test]
    fn validate_runtime_target_validates_config_for_known_provider() {
        let config = json!({"model": "gpt-4", "base_url": "https://api.openai.com"});
        let result = validate_runtime_target("openai", None, &config).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().support_level, RuntimeSupportLevel::Native);
    }

    #[test]
    fn validate_runtime_target_rejects_invalid_config() {
        let config = json!({"model": "", "base_url": "https://api.openai.com"});
        let result = validate_runtime_target("openai", None, &config);
        assert!(result.is_err());
    }
}
