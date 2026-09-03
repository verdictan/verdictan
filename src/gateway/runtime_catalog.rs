// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::BTreeSet;

use crate::error::CliError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeCategory {
    CatalogRoot,
    UpstreamApi,
    NetworkAdapter,
    LocalOrScriptRuntime,
    InteractionOrEvaluatorRuntime,
    AgentOrSdkRuntime,
}

impl RuntimeCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CatalogRoot => "catalog-root",
            Self::UpstreamApi => "upstream-api",
            Self::NetworkAdapter => "network-adapter",
            Self::LocalOrScriptRuntime => "local-or-script-runtime",
            Self::InteractionOrEvaluatorRuntime => "interaction-or-evaluator-runtime",
            Self::AgentOrSdkRuntime => "agent-or-sdk-runtime",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuntimeCatalogEntry {
    pub doc_id: &'static str,
    pub page: &'static str,
    pub category: RuntimeCategory,
    pub required_parity_lane: &'static str,
}

impl RuntimeCatalogEntry {
    pub const fn new(
        doc_id: &'static str,
        page: &'static str,
        category: RuntimeCategory,
        required_parity_lane: &'static str,
    ) -> Self {
        Self {
            doc_id,
            page,
            category,
            required_parity_lane,
        }
    }
}

pub const EXPECTED_VERDICTAN_PROVIDER_DOC_COUNT: usize = 77;

const INVENTORY: [RuntimeCatalogEntry; EXPECTED_VERDICTAN_PROVIDER_DOC_COUNT] = [
    RuntimeCatalogEntry::new(
        "DOC-001",
        "index.md",
        RuntimeCategory::CatalogRoot,
        "catalog-and-docs",
    ),
    RuntimeCatalogEntry::new(
        "DOC-002",
        "ai21.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-003",
        "aimlapi.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-004",
        "alibaba.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-005",
        "anthropic.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-006",
        "aws-bedrock.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-007",
        "azure.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-008",
        "browser.md",
        RuntimeCategory::InteractionOrEvaluatorRuntime,
        "interaction-or-evaluator-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-009",
        "cerebras.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-010",
        "claude-agent-sdk.md",
        RuntimeCategory::AgentOrSdkRuntime,
        "agent-or-sdk-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-011",
        "cloudera.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-012",
        "cloudflare-ai.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-013",
        "cloudflare-gateway.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-014",
        "cohere.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-015",
        "cometapi.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-016",
        "custom-api.md",
        RuntimeCategory::NetworkAdapter,
        "network-adapter",
    ),
    RuntimeCatalogEntry::new(
        "DOC-017",
        "custom-script.md",
        RuntimeCategory::LocalOrScriptRuntime,
        "local-or-script-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-018",
        "databricks.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-019",
        "deepseek.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-020",
        "docker.md",
        RuntimeCategory::LocalOrScriptRuntime,
        "local-or-script-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-021",
        "echo.md",
        RuntimeCategory::LocalOrScriptRuntime,
        "local-or-script-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-022",
        "elevenlabs.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-023",
        "envoy.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-024",
        "f5.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-025",
        "fal.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-026",
        "fireworks.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-027",
        "github.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-028",
        "go.md",
        RuntimeCategory::LocalOrScriptRuntime,
        "local-or-script-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-029",
        "google.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-030",
        "groq.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-031",
        "helicone.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-032",
        "http.md",
        RuntimeCategory::NetworkAdapter,
        "network-adapter",
    ),
    RuntimeCatalogEntry::new(
        "DOC-033",
        "huggingface.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-034",
        "hyperbolic.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-035",
        "ibm-bam.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-036",
        "bedrock-agents.md",
        RuntimeCategory::AgentOrSdkRuntime,
        "agent-or-sdk-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-037",
        "jfrog.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-038",
        "litellm.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-039",
        "llama.cpp.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-040",
        "llamaApi.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-041",
        "llamafile.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-042",
        "localai.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-043",
        "manual-input.md",
        RuntimeCategory::LocalOrScriptRuntime,
        "local-or-script-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-044",
        "mcp.md",
        RuntimeCategory::NetworkAdapter,
        "network-adapter",
    ),
    RuntimeCatalogEntry::new(
        "DOC-045",
        "mistral.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-046",
        "modelslab.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-047",
        "nscale.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-048",
        "ollama.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-049",
        "openai-agents.md",
        RuntimeCategory::AgentOrSdkRuntime,
        "agent-or-sdk-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-050",
        "openai-chatkit.md",
        RuntimeCategory::AgentOrSdkRuntime,
        "agent-or-sdk-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-051",
        "openai-codex-sdk.md",
        RuntimeCategory::AgentOrSdkRuntime,
        "agent-or-sdk-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-052",
        "openai.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-053",
        "openclaw.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-054",
        "opencode-sdk.md",
        RuntimeCategory::AgentOrSdkRuntime,
        "agent-or-sdk-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-055",
        "openllm.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-056",
        "openrouter.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-057",
        "perplexity.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-058",
        "python.md",
        RuntimeCategory::LocalOrScriptRuntime,
        "local-or-script-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-059",
        "quiverai.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-060",
        "replicate.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-061",
        "ruby.md",
        RuntimeCategory::LocalOrScriptRuntime,
        "local-or-script-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-062",
        "sagemaker.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-063",
        "sequence.md",
        RuntimeCategory::InteractionOrEvaluatorRuntime,
        "interaction-or-evaluator-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-064",
        "simulated-user.md",
        RuntimeCategory::InteractionOrEvaluatorRuntime,
        "interaction-or-evaluator-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-065",
        "slack.md",
        RuntimeCategory::InteractionOrEvaluatorRuntime,
        "interaction-or-evaluator-runtime",
    ),
    RuntimeCatalogEntry::new(
        "DOC-066",
        "snowflake.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-067",
        "text-generation-webui.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-068",
        "togetherai.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-069",
        "transformers.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-070",
        "truefoundry.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-071",
        "vercel.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-072",
        "vertex.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-073",
        "vllm.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-074",
        "voyage.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-075",
        "watsonx.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
    RuntimeCatalogEntry::new(
        "DOC-076",
        "websocket.md",
        RuntimeCategory::NetworkAdapter,
        "network-adapter",
    ),
    RuntimeCatalogEntry::new(
        "DOC-077",
        "xai.md",
        RuntimeCategory::UpstreamApi,
        "upstream-api",
    ),
];

pub fn verdictan_runtime_catalog() -> &'static [RuntimeCatalogEntry] {
    &INVENTORY
}

fn verify_verdictan_runtime_catalog() -> Result<(), CliError> {
    if INVENTORY.len() != EXPECTED_VERDICTAN_PROVIDER_DOC_COUNT {
        return Err(CliError::internal(format!(
            "verdictan runtime catalog count mismatch: expected {} entries, found {}",
            EXPECTED_VERDICTAN_PROVIDER_DOC_COUNT,
            INVENTORY.len()
        )));
    }

    let mut doc_ids = BTreeSet::new();
    let mut pages = BTreeSet::new();
    for entry in INVENTORY {
        if !doc_ids.insert(entry.doc_id) {
            return Err(CliError::internal(format!(
                "verdictan runtime catalog has a duplicate doc id: {}",
                entry.doc_id
            )));
        }
        if !pages.insert(entry.page) {
            return Err(CliError::internal(format!(
                "verdictan runtime catalog has a duplicate page entry: {}",
                entry.page
            )));
        }
    }

    Ok(())
}

pub fn page_to_runtime_mapping(page: &str) -> Option<&'static RuntimeCatalogEntry> {
    verdictan_runtime_catalog()
        .iter()
        .find(|entry| entry.page == page)
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

    // --- RuntimeCategory ---

    #[test]
    fn category_as_str_values() {
        assert_eq!(RuntimeCategory::CatalogRoot.as_str(), "catalog-root");
        assert_eq!(RuntimeCategory::UpstreamApi.as_str(), "upstream-api");
        assert_eq!(RuntimeCategory::NetworkAdapter.as_str(), "network-adapter");
        assert_eq!(
            RuntimeCategory::LocalOrScriptRuntime.as_str(),
            "local-or-script-runtime"
        );
        assert_eq!(
            RuntimeCategory::InteractionOrEvaluatorRuntime.as_str(),
            "interaction-or-evaluator-runtime"
        );
        assert_eq!(
            RuntimeCategory::AgentOrSdkRuntime.as_str(),
            "agent-or-sdk-runtime"
        );
    }

    // --- Catalog constants ---

    #[test]
    fn inventory_has_expected_count() {
        assert_eq!(
            verdictan_runtime_catalog().len(),
            EXPECTED_VERDICTAN_PROVIDER_DOC_COUNT
        );
    }

    // --- verify_verdictan_runtime_catalog ---

    #[test]
    fn verify_catalog_succeeds() {
        verify_verdictan_runtime_catalog().unwrap();
    }

    #[test]
    fn catalog_has_no_duplicate_doc_ids() {
        let catalog = verdictan_runtime_catalog();
        let mut seen = std::collections::BTreeSet::new();
        for entry in catalog {
            assert!(
                seen.insert(entry.doc_id),
                "duplicate doc_id: {}",
                entry.doc_id
            );
        }
    }

    #[test]
    fn catalog_has_no_duplicate_pages() {
        let catalog = verdictan_runtime_catalog();
        let mut seen = std::collections::BTreeSet::new();
        for entry in catalog {
            assert!(seen.insert(entry.page), "duplicate page: {}", entry.page);
        }
    }

    // --- page_to_runtime_mapping ---

    #[test]
    fn page_mapping_known_page() {
        let entry = page_to_runtime_mapping("openai.md").unwrap();
        assert_eq!(entry.doc_id, "DOC-052");
        assert_eq!(entry.category, RuntimeCategory::UpstreamApi);
    }

    #[test]
    fn page_mapping_index() {
        let entry = page_to_runtime_mapping("index.md").unwrap();
        assert_eq!(entry.category, RuntimeCategory::CatalogRoot);
    }

    #[test]
    fn page_mapping_unknown_returns_none() {
        assert!(page_to_runtime_mapping("nonexistent.md").is_none());
    }

    #[test]
    fn page_mapping_agent_sdk_category() {
        let entry = page_to_runtime_mapping("claude-agent-sdk.md").unwrap();
        assert_eq!(entry.category, RuntimeCategory::AgentOrSdkRuntime);
    }

    #[test]
    fn page_mapping_network_adapter_category() {
        let entry = page_to_runtime_mapping("websocket.md").unwrap();
        assert_eq!(entry.category, RuntimeCategory::NetworkAdapter);
    }

    #[test]
    fn page_mapping_local_script_category() {
        let entry = page_to_runtime_mapping("python.md").unwrap();
        assert_eq!(entry.category, RuntimeCategory::LocalOrScriptRuntime);
    }

    #[test]
    fn page_mapping_interaction_category() {
        let entry = page_to_runtime_mapping("browser.md").unwrap();
        assert_eq!(
            entry.category,
            RuntimeCategory::InteractionOrEvaluatorRuntime
        );
    }

    // --- RuntimeCatalogEntry::new ---

    #[test]
    fn catalog_entry_new() {
        let entry = RuntimeCatalogEntry::new(
            "DOC-999",
            "test.md",
            RuntimeCategory::UpstreamApi,
            "upstream-api",
        );
        assert_eq!(entry.doc_id, "DOC-999");
        assert_eq!(entry.page, "test.md");
        assert_eq!(entry.category, RuntimeCategory::UpstreamApi);
        assert_eq!(entry.required_parity_lane, "upstream-api");
    }

    // --- Doc ID sequential ordering ---

    #[test]
    fn doc_ids_are_sequential() {
        let catalog = verdictan_runtime_catalog();
        for (i, entry) in catalog.iter().enumerate() {
            let expected = format!("DOC-{:03}", i + 1);
            assert_eq!(
                entry.doc_id, expected,
                "entry at index {i} has wrong doc_id"
            );
        }
    }
}
