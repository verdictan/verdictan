// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::{json, Value};
use std::{
    future::Future,
    pin::Pin,
    sync::{mpsc, OnceLock},
};

use crate::gateway::{
    cache::cosine_similarity,
    provider_auth::{resolve_provider_type, ProviderType},
    providers::{ProviderRegistry, ProviderTarget},
};

pub(crate) fn semantic_similarity_with_provider(
    output: &str,
    reference: &str,
    provider_id: &str,
    registry: &ProviderRegistry,
) -> Result<(f64, Value), String> {
    let target = registry
        .targets
        .iter()
        .find(|target| target.id == provider_id)
        .ok_or_else(|| format!("embedding provider '{provider_id}' not found"))?;

    let embeddings = embed_texts(target, &[output, reference])?;
    if embeddings.len() < 2 {
        return Err("embedding provider did not return two embeddings".to_string());
    }

    Ok((
        cosine_similarity(&embeddings[0], &embeddings[1]).clamp(0.0, 1.0),
        json!({
            "provider": provider_id,
            "provider_type": resolve_provider_type(target).as_str(),
            "embedding_backend": "remote",
        }),
    ))
}

pub(crate) fn embed_texts_with_provider(
    provider_id: &str,
    texts: &[&str],
    registry: &ProviderRegistry,
) -> Result<Vec<Vec<f64>>, String> {
    let target = registry
        .targets
        .iter()
        .find(|target| target.id == provider_id)
        .ok_or_else(|| format!("embedding provider '{provider_id}' not found"))?;

    embed_texts(target, texts)
}

pub(crate) fn embed_text_with_provider(
    provider_id: &str,
    text: &str,
    registry: &ProviderRegistry,
) -> Result<Vec<f64>, String> {
    let mut embeddings = embed_texts_with_provider(provider_id, &[text], registry)?;
    let embedding = embeddings
        .drain(..)
        .next()
        .ok_or_else(|| "embedding provider did not return an embedding".to_string())?;
    Ok(embedding)
}

fn embed_texts(target: &ProviderTarget, texts: &[&str]) -> Result<Vec<Vec<f64>>, String> {
    match resolve_provider_type(target) {
        ProviderType::OpenAI
        | ProviderType::Generic
        | ProviderType::AzureOpenAI
        | ProviderType::Databricks
        | ProviderType::CloudflareAi => embed_openai_compatible(target, texts),
        ProviderType::Cohere => embed_cohere(target, texts),
        ProviderType::HuggingFace => embed_huggingface(target, texts),
        ProviderType::WatsonX => embed_watsonx(target, texts),
        ProviderType::GoogleAiStudio => embed_google_ai_studio(target, texts),
        ProviderType::GoogleVertex => embed_google_vertex(target, texts),
        other => Err(format!(
            "provider type '{}' does not support remote embeddings in semantic-similarity yet",
            other.as_str()
        )),
    }
}

struct SharedEmbeddingRuntime {
    job_tx: tokio::sync::mpsc::UnboundedSender<EmbeddingJob>,
}

impl SharedEmbeddingRuntime {
    fn run<T, F>(&self, future: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, String>>,
        F: Send + 'static,
    {
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let job = Box::pin(async move {
            let _ = result_tx.send(future.await);
        });
        self.job_tx
            .send(job)
            .map_err(|_| "embedding runtime thread is unavailable".to_string())?;
        result_rx
            .recv()
            .map_err(|_| "embedding runtime thread did not return a result".to_string())?
    }
}

fn shared_embedding_runtime() -> Result<&'static SharedEmbeddingRuntime, String> {
    static RUNTIME: OnceLock<Result<SharedEmbeddingRuntime, String>> = OnceLock::new();

    RUNTIME
        .get_or_init(|| {
            let (job_tx, mut job_rx) = tokio::sync::mpsc::unbounded_channel::<EmbeddingJob>();
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            std::thread::Builder::new()
                .name("verdictan-embeddings".to_string())
                .spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            let _ = ready_tx
                                .send(Err(format!("failed to create embedding runtime: {error}")));
                            return;
                        }
                    };

                    let _ = ready_tx.send(Ok(()));
                    runtime.block_on(async move {
                        while let Some(job) = job_rx.recv().await {
                            job.await;
                        }
                    });
                })
                .map_err(|error| format!("failed to spawn embedding runtime thread: {error}"))?;
            ready_rx
                .recv()
                .map_err(|_| "embedding runtime thread did not initialize".to_string())??;
            Ok(SharedEmbeddingRuntime { job_tx })
        })
        .as_ref()
        .map_err(Clone::clone)
}

fn shared_embedding_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

fn run_async<T, F>(future: F) -> Result<T, String>
where
    T: Send + 'static,
    F: Future<Output = Result<T, String>> + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| handle.block_on(future))
        }
        Ok(_) | Err(_) => shared_embedding_runtime()?.run(future),
    }
}

type EmbeddingJob = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

fn join_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/v1") && path.starts_with("/v1/") {
        format!("{base}{}", &path[3..])
    } else {
        format!("{base}{path}")
    }
}

fn parse_embedding_vector(value: &Value) -> Option<Vec<f64>> {
    value.as_array().map(|values| {
        values
            .iter()
            .filter_map(|item| item.as_f64())
            .collect::<Vec<_>>()
    })
}

fn parse_openai_embeddings(payload: &Value) -> Result<Vec<Vec<f64>>, String> {
    payload
        .get("data")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("embedding").and_then(parse_embedding_vector))
                .collect::<Vec<_>>()
        })
        .filter(|embeddings| !embeddings.is_empty())
        .ok_or_else(|| "embedding response did not include data[].embedding".to_string())
}

fn embed_openai_compatible(
    target: &ProviderTarget,
    texts: &[&str],
) -> Result<Vec<Vec<f64>>, String> {
    let provider_type = resolve_provider_type(target);
    let inputs = texts
        .iter()
        .map(|text| (*text).to_string())
        .collect::<Vec<_>>();
    let (url, auth_header_name, auth_header_value) = if provider_type == ProviderType::AzureOpenAI {
        let deployment = target
            .azure_deployment
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(target.model.as_str());
        let api_version = target.azure_api_version.as_deref().unwrap_or("2024-02-01");
        (
            format!(
                "{}/openai/deployments/{deployment}/embeddings?api-version={api_version}",
                target.base_url.trim_end_matches('/')
            ),
            "api-key".to_string(),
            target.api_key.clone(),
        )
    } else {
        (
            join_url(&target.base_url, "/v1/embeddings"),
            target.api_key_header.clone(),
            format!("{}{}", target.api_key_prefix, target.api_key),
        )
    };

    let model = target.model.clone();
    let timeout = target.timeout;
    let client = shared_embedding_client().clone();
    let payload: Value = run_async(async move {
        client
            .post(url)
            .timeout(timeout)
            .header(auth_header_name, auth_header_value)
            .json(&json!({
                "model": model,
                "input": inputs,
            }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| format!("embedding request failed: {error}"))?
            .json()
            .await
            .map_err(|error| format!("invalid embedding response payload: {error}"))
    })?;
    parse_openai_embeddings(&payload)
}

fn embed_cohere(target: &ProviderTarget, texts: &[&str]) -> Result<Vec<Vec<f64>>, String> {
    let base_url = target.base_url.clone();
    let api_key = target.api_key.clone();
    let model = target.model.clone();
    let timeout = target.timeout;
    let client = shared_embedding_client().clone();
    let inputs = texts
        .iter()
        .map(|text| (*text).to_string())
        .collect::<Vec<_>>();
    let payload: Value = run_async(async move {
        client
            .post(join_url(&base_url, "/v2/embed"))
            .timeout(timeout)
            .header("Authorization", format!("Bearer {api_key}"))
            .json(&json!({
                "model": model,
                "texts": inputs,
                "input_type": "search_document",
                "embedding_types": ["float"],
            }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| format!("cohere embedding request failed: {error}"))?
            .json()
            .await
            .map_err(|error| format!("invalid cohere embedding response: {error}"))
    })?;
    if let Some(vectors) = payload
        .get("embeddings")
        .and_then(|value| value.get("float"))
        .and_then(|value| value.as_array())
    {
        let embeddings = vectors
            .iter()
            .filter_map(parse_embedding_vector)
            .collect::<Vec<_>>();
        if !embeddings.is_empty() {
            return Ok(embeddings);
        }
    }
    payload
        .get("embeddings")
        .and_then(|value| value.as_array())
        .map(|vectors| {
            vectors
                .iter()
                .filter_map(parse_embedding_vector)
                .collect::<Vec<_>>()
        })
        .filter(|embeddings| !embeddings.is_empty())
        .ok_or_else(|| "cohere embedding response did not include embeddings".to_string())
}

fn embed_huggingface(target: &ProviderTarget, texts: &[&str]) -> Result<Vec<Vec<f64>>, String> {
    let base_url = target.base_url.clone();
    let model = target.model.clone();
    let api_key = target.api_key.clone();
    let timeout = target.timeout;
    let client = shared_embedding_client().clone();
    let mut embeddings = Vec::new();
    for text in texts {
        let text = (*text).to_string();
        let base_url = base_url.clone();
        let model = model.clone();
        let api_key = api_key.clone();
        let client = client.clone();
        let payload: Value = run_async(async move {
            client
                .post(join_url(&base_url, &format!("/models/{model}")))
                .timeout(timeout)
                .header("Authorization", format!("Bearer {api_key}"))
                .json(&json!({
                    "inputs": text,
                    "options": {"wait_for_model": true},
                }))
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|error| format!("huggingface embedding request failed: {error}"))?
                .json()
                .await
                .map_err(|error| format!("invalid huggingface embedding response: {error}"))
        })?;

        let embedding = parse_embedding_vector(&payload)
            .or_else(|| payload.get("embedding").and_then(parse_embedding_vector))
            .or_else(|| {
                payload
                    .as_array()
                    .and_then(|items| items.first())
                    .and_then(|item| {
                        parse_embedding_vector(item)
                            .or_else(|| item.get("embedding").and_then(parse_embedding_vector))
                    })
            })
            .ok_or_else(|| "huggingface embedding response did not include a vector".to_string())?;
        embeddings.push(embedding);
    }
    Ok(embeddings)
}

fn embed_watsonx(target: &ProviderTarget, texts: &[&str]) -> Result<Vec<Vec<f64>>, String> {
    let base_url = target.base_url.clone();
    let model = target.model.clone();
    let token = std::env::var("WATSONX_ACCESS_TOKEN").unwrap_or_else(|_| target.api_key.clone());
    let timeout = target.timeout;
    let client = shared_embedding_client().clone();
    let inputs = texts
        .iter()
        .map(|text| (*text).to_string())
        .collect::<Vec<_>>();
    let payload: Value = run_async(async move {
        client
            .post(join_url(
                &base_url,
                "/ml/v1/text/embeddings?version=2024-05-01",
            ))
            .timeout(timeout)
            .header("Authorization", format!("Bearer {token}"))
            .json(&json!({
                "model_id": model,
                "inputs": inputs,
            }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| format!("watsonx embedding request failed: {error}"))?
            .json()
            .await
            .map_err(|error| format!("invalid watsonx embedding response: {error}"))
    })?;
    payload
        .get("results")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("embedding").and_then(parse_embedding_vector))
                .collect::<Vec<_>>()
        })
        .filter(|embeddings| !embeddings.is_empty())
        .ok_or_else(|| "watsonx embedding response did not include results[].embedding".to_string())
}

fn embed_google_ai_studio(
    target: &ProviderTarget,
    texts: &[&str],
) -> Result<Vec<Vec<f64>>, String> {
    let base_url = target.base_url.clone();
    let model = target.model.clone();
    let api_key = target.api_key.clone();
    let timeout = target.timeout;
    let client = shared_embedding_client().clone();
    let mut embeddings = Vec::new();
    for text in texts {
        let base_url = base_url.clone();
        let model = model.clone();
        let api_key = api_key.clone();
        let text = (*text).to_string();
        let client = client.clone();
        let payload: Value = run_async(async move {
            client
                .post(join_url(
                    &base_url,
                    &format!("/v1beta/models/{model}:embedContent"),
                ))
                .timeout(timeout)
                .header("x-goog-api-key", api_key)
                .json(&json!({
                    "content": {"parts": [{"text": text}]},
                }))
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|error| format!("google ai studio embedding request failed: {error}"))?
                .json()
                .await
                .map_err(|error| format!("invalid google ai studio embedding response: {error}"))
        })?;
        let embedding = payload
            .get("embedding")
            .and_then(|value| value.get("values"))
            .and_then(parse_embedding_vector)
            .ok_or_else(|| {
                "google ai studio embedding response did not include embedding.values".to_string()
            })?;
        embeddings.push(embedding);
    }
    Ok(embeddings)
}

fn embed_google_vertex(target: &ProviderTarget, texts: &[&str]) -> Result<Vec<Vec<f64>>, String> {
    let project = target
        .gcp_project
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!(
                "provider '{}': google-vertex embeddings require gcp_project",
                target.id
            )
        })?
        .to_string();
    let region = target
        .gcp_region
        .as_deref()
        .unwrap_or("us-central1")
        .to_string();
    let base_url = target.base_url.clone();
    let model = target.model.clone();
    let token = if !target.api_key.is_empty() {
        target.api_key.clone()
    } else {
        std::env::var("GOOGLE_VERTEX_ACCESS_TOKEN").map_err(|_| {
            format!(
                "provider '{}': google-vertex embeddings require api_key or GOOGLE_VERTEX_ACCESS_TOKEN",
                target.id
            )
        })?
    };
    let timeout = target.timeout;
    let client = shared_embedding_client().clone();
    let mut embeddings = Vec::new();
    for text in texts {
        let base_url = base_url.clone();
        let project = project.clone();
        let region = region.clone();
        let model = model.clone();
        let token = token.clone();
        let text = (*text).to_string();
        let client = client.clone();
        let payload: Value = run_async(async move {
            client
                .post(join_url(
                    &base_url,
                    &format!(
                        "/v1/projects/{project}/locations/{region}/publishers/google/models/{model}:predict"
                    ),
                ))
                .timeout(timeout)
                .header("Authorization", format!("Bearer {token}"))
                .json(&json!({
                    "instances": [{"content": text}],
                }))
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|error| format!("google vertex embedding request failed: {error}"))?
                .json()
                .await
                .map_err(|error| format!("invalid google vertex embedding response: {error}"))
        })?;
        let embedding = payload
            .get("predictions")
            .and_then(|value| value.as_array())
            .and_then(|items| items.first())
            .and_then(|item| item.get("embeddings"))
            .and_then(|value| value.get("values"))
            .and_then(parse_embedding_vector)
            .ok_or_else(|| {
                "google vertex embedding response did not include predictions[].embeddings.values"
                    .to_string()
            })?;
        embeddings.push(embedding);
    }
    Ok(embeddings)
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
    use crate::gateway::provider_auth::ProviderType;
    use crate::gateway::providers::ProviderTarget;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn acquire_test_lock() -> std::sync::MutexGuard<'static, ()> {
        test_lock()
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn base_target(provider_type: ProviderType, base_url: String) -> ProviderTarget {
        ProviderTarget {
            id: "embedding-provider".to_string(),
            provider: provider_type.as_str().to_string(),
            model: "embed-model".to_string(),
            execution_target: None,
            mcp_bridge: None,
            description: None,
            base_url,
            api_key: "sk-test".to_string(),
            api_key_header: "Authorization".to_string(),
            api_key_prefix: "Bearer ".to_string(),
            secret_key_ref: None,
            path_template: None,
            headers: HashMap::new(),
            timeout: Duration::from_secs(2),
            stream_timeout: None,
            max_context_tokens: None,
            max_messages: None,
            data_policy: None,
            pricing: None,
            models: Vec::new(),
            data_collection: None,
            zdr: false,
            region: None,
            quantizations: None,
            weight: None,
            provider_type: Some(provider_type),
            format: None,
            anthropic_version: None,
            aws_region: None,
            aws_profile: None,
            bedrock_model_family: None,
            watsonx_api_version: None,
            watsonx_project_id: None,
            watsonx_space_id: None,
            gcp_project: None,
            gcp_region: None,
            azure_api_version: None,
            azure_deployment: None,
            oauth2: None,
            health_probe: None,
            allow_insecure_tls: false,
            escalation_routing: None,
            required: false,
            data_residency: None,
            certifications: None,
        }
    }

    fn spawn_json_server(
        body: Value,
    ) -> (
        String,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        spawn_json_server_requests(1, body)
    }

    fn spawn_json_server_requests(
        request_count: usize,
        body: Value,
    ) -> (
        String,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("server address");
        let (request_tx, request_rx) = std::sync::mpsc::sync_channel(request_count);
        let body_text = body.to_string();

        let handle = std::thread::spawn(move || {
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().expect("accept request");
                let mut buffer = [0_u8; 8192];
                let read = stream.read(&mut buffer).expect("read request");
                let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let _ = request_tx.send(request);

                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body_text.len(),
                    body_text
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
            }
        });

        (format!("http://{address}"), request_rx, handle)
    }

    #[test]
    fn shared_embedding_client_reuses_single_instance() {
        let _guard = acquire_test_lock();
        assert!(std::ptr::eq(
            shared_embedding_client(),
            shared_embedding_client()
        ));
    }

    #[test]
    fn run_async_reuses_shared_runtime_without_tokio_context() {
        let _guard = acquire_test_lock();
        let value = run_async(async { Ok::<_, String>(7) }).expect("shared runtime result");
        assert_eq!(value, 7);
    }

    #[test]
    fn run_async_handles_current_thread_runtime() {
        let _guard = acquire_test_lock();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let value = runtime
            .block_on(async { run_async(async { Ok::<_, String>(11) }) })
            .expect("current-thread bridge result");
        assert_eq!(value, 11);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_async_handles_multithread_runtime() {
        let value = run_async(async { Ok::<_, String>(13) }).expect("multi-thread bridge result");
        assert_eq!(value, 13);
    }

    #[test]
    fn policy_embeddings_join_and_parse_helpers_cover_edge_cases() {
        assert_eq!(
            join_url("https://example.test/v1/", "/v1/embeddings"),
            "https://example.test/v1/embeddings"
        );
        assert_eq!(
            parse_embedding_vector(&json!([1.0, "skip", 2.5])),
            Some(vec![1.0, 2.5])
        );
        assert_eq!(
            parse_openai_embeddings(&json!({"data": [{"embedding": [0.1, 0.2]}]}))
                .expect("openai embedding payload"),
            vec![vec![0.1, 0.2]]
        );
        assert!(parse_openai_embeddings(&json!({"data": []}))
            .expect_err("missing embeddings")
            .contains("data[].embedding"));
    }

    #[test]
    fn policy_embeddings_openai_compatible_posts_expected_path_and_parses_vectors() {
        let _guard = acquire_test_lock();
        let (url, requests, handle) = spawn_json_server(json!({
            "data": [
                {"embedding": [1.0, 0.0]},
                {"embedding": [0.0, 1.0]}
            ]
        }));
        let target = base_target(ProviderType::OpenAI, format!("{url}/v1"));

        let embeddings =
            embed_openai_compatible(&target, &["hello", "world"]).expect("openai embeddings");
        let request = requests.recv().expect("captured request");
        handle.join().expect("server join");

        assert_eq!(embeddings, vec![vec![1.0, 0.0], vec![0.0, 1.0]]);
        assert!(request.contains("POST /v1/embeddings HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer sk-test"));
        assert!(request.contains("\"input\":[\"hello\",\"world\"]"));
    }

    #[test]
    fn policy_embeddings_cohere_and_huggingface_parse_provider_payloads() {
        let _guard = acquire_test_lock();
        let (cohere_url, cohere_requests, cohere_handle) = spawn_json_server(json!({
            "embeddings": {
                "float": [[0.1, 0.2], [0.3, 0.4]]
            }
        }));
        let cohere_target = base_target(ProviderType::Cohere, cohere_url);
        let cohere_embeddings =
            embed_cohere(&cohere_target, &["first", "second"]).expect("cohere embeddings");
        let cohere_request = cohere_requests.recv().expect("captured cohere request");
        cohere_handle.join().expect("cohere server join");

        assert_eq!(cohere_embeddings, vec![vec![0.1, 0.2], vec![0.3, 0.4]]);
        assert!(cohere_request.contains("POST /v2/embed HTTP/1.1"));
        assert!(cohere_request.contains("\"embedding_types\":[\"float\"]"));

        let (hf_url, hf_requests, hf_handle) = spawn_json_server(json!([0.5, 0.25, 0.125]));
        let hf_target = base_target(ProviderType::HuggingFace, hf_url);
        let hf_embeddings =
            embed_huggingface(&hf_target, &["query"]).expect("huggingface embeddings");
        let hf_request = hf_requests.recv().expect("captured huggingface request");
        hf_handle.join().expect("huggingface server join");

        assert_eq!(hf_embeddings, vec![vec![0.5, 0.25, 0.125]]);
        assert!(hf_request.contains("POST /models/embed-model HTTP/1.1"));
        assert!(hf_request.contains("\"inputs\":\"query\""));
    }

    #[test]
    fn policy_embeddings_google_vertex_and_unsupported_types_report_clear_errors() {
        let _guard = acquire_test_lock();

        let unsupported = base_target(ProviderType::Anthropic, "https://api.example.test".into());
        assert!(embed_texts(&unsupported, &["hello"])
            .expect_err("unsupported type")
            .contains("does not support remote embeddings"));

        let missing_project = base_target(
            ProviderType::GoogleVertex,
            "https://aiplatform.googleapis.com".into(),
        );
        assert!(embed_google_vertex(&missing_project, &["hello"])
            .expect_err("missing gcp_project")
            .contains("require gcp_project"));

        let mut missing_token = base_target(
            ProviderType::GoogleVertex,
            "https://aiplatform.googleapis.com".into(),
        );
        missing_token.gcp_project = Some("project-1".to_string());
        missing_token.api_key.clear();
        assert!(embed_google_vertex(&missing_token, &["hello"])
            .expect_err("missing token")
            .contains("require api_key or GOOGLE_VERTEX_ACCESS_TOKEN"));
    }

    #[test]
    fn policy_embeddings_azure_openai_posts_deployment_path() {
        let _guard = acquire_test_lock();
        let (url, requests, handle) = spawn_json_server(json!({
            "data": [{"embedding": [0.25, 0.75]}]
        }));
        let mut target = base_target(ProviderType::AzureOpenAI, url);
        target.azure_deployment = Some("embed-deploy".to_string());
        target.azure_api_version = Some("2024-05-01".to_string());
        target.api_key_header = "api-key".to_string();
        target.api_key_prefix.clear();

        let embeddings =
            embed_openai_compatible(&target, &["azure text"]).expect("azure embeddings");
        let request = requests.recv().expect("captured azure request");
        handle.join().expect("azure server join");

        assert_eq!(embeddings, vec![vec![0.25, 0.75]]);
        assert!(request.contains("POST /openai/deployments/embed-deploy/embeddings"));
        assert!(request.contains("api-version=2024-05-01"));
        assert!(request.contains("api-key: sk-test"));
    }

    #[test]
    fn policy_embeddings_watsonx_and_google_providers_parse_vectors() {
        let _guard = acquire_test_lock();

        let (watsonx_url, watsonx_requests, watsonx_handle) = spawn_json_server(json!({
            "results": [{"embedding": [1.0, 0.5]}]
        }));
        let watsonx_target = base_target(ProviderType::WatsonX, watsonx_url);
        let watsonx_embeddings =
            embed_watsonx(&watsonx_target, &["watson query"]).expect("watsonx embeddings");
        let watsonx_request = watsonx_requests.recv().expect("captured watsonx request");
        watsonx_handle.join().expect("watsonx server join");
        assert_eq!(watsonx_embeddings, vec![vec![1.0, 0.5]]);
        assert!(watsonx_request.contains("POST /ml/v1/text/embeddings"));

        let (studio_url, studio_requests, studio_handle) = spawn_json_server(json!({
            "embedding": {"values": [0.2, 0.8]}
        }));
        let studio_target = base_target(ProviderType::GoogleAiStudio, studio_url);
        let studio_embeddings =
            embed_google_ai_studio(&studio_target, &["studio text"]).expect("studio embeddings");
        let studio_request = studio_requests.recv().expect("captured studio request");
        studio_handle.join().expect("studio server join");
        assert_eq!(studio_embeddings, vec![vec![0.2, 0.8]]);
        assert!(studio_request.contains("POST /v1beta/models/embed-model:embedContent"));
    }

    #[test]
    fn policy_embeddings_google_vertex_success_and_provider_wrappers() {
        let _guard = acquire_test_lock();
        let vertex_body = json!({
            "predictions": [{"embeddings": {"values": [0.9, 0.1]}}]
        });

        let (url, requests, handle) = spawn_json_server_requests(4, vertex_body);
        let mut target = base_target(ProviderType::GoogleVertex, url);
        target.gcp_project = Some("demo-project".to_string());
        target.gcp_region = Some("us-east1".to_string());

        let embeddings = embed_google_vertex(&target, &["vertex text"]).expect("vertex embeddings");
        let request = requests.recv().expect("captured vertex request");
        assert_eq!(embeddings, vec![vec![0.9, 0.1]]);
        assert!(request.contains("/projects/demo-project/locations/us-east1/"));

        let registry = ProviderRegistry {
            targets: vec![target],
            ..Default::default()
        };
        let single = embed_text_with_provider("embedding-provider", "hello", &registry)
            .expect("single embedding");
        assert_eq!(single, vec![0.9, 0.1]);

        let (score, details) =
            semantic_similarity_with_provider("hello", "hello", "embedding-provider", &registry)
                .expect("semantic similarity");
        assert!((score - 1.0).abs() < f64::EPSILON);
        assert_eq!(details["embedding_backend"], "remote");
        handle.join().expect("vertex server join");
    }

    #[test]
    fn policy_embeddings_cohere_legacy_and_huggingface_nested_payloads() {
        let _guard = acquire_test_lock();

        let (cohere_url, cohere_requests, cohere_handle) = spawn_json_server(json!({
            "embeddings": [[0.4, 0.6]]
        }));
        let cohere_target = base_target(ProviderType::Cohere, cohere_url);
        let cohere_embeddings =
            embed_cohere(&cohere_target, &["legacy"]).expect("legacy cohere embeddings");
        let cohere_request = cohere_requests
            .recv()
            .expect("captured legacy cohere request");
        cohere_handle.join().expect("legacy cohere server join");
        assert_eq!(cohere_embeddings, vec![vec![0.4, 0.6]]);
        assert!(cohere_request.contains("POST /v2/embed HTTP/1.1"));

        let (hf_url, hf_requests, hf_handle) = spawn_json_server(json!([0.3, 0.7]));
        let hf_target = base_target(ProviderType::HuggingFace, hf_url);
        let hf_embeddings =
            embed_huggingface(&hf_target, &["nested"]).expect("nested huggingface embeddings");
        let hf_request = hf_requests
            .recv()
            .expect("captured nested huggingface request");
        hf_handle.join().expect("nested huggingface server join");
        assert_eq!(hf_embeddings, vec![vec![0.3, 0.7]]);
        assert!(hf_request.contains("POST /models/embed-model HTTP/1.1"));
    }

    #[test]
    fn policy_embeddings_reports_when_provider_returns_too_few_vectors() {
        let _guard = acquire_test_lock();
        let (url, _requests, handle) = spawn_json_server(json!({
            "data": [{"embedding": [1.0, 0.0]}]
        }));
        let target = base_target(ProviderType::OpenAI, format!("{url}/v1"));
        let registry = ProviderRegistry {
            targets: vec![target],
            ..Default::default()
        };
        let error =
            semantic_similarity_with_provider("left", "right", "embedding-provider", &registry)
                .expect_err("single embedding should fail semantic similarity");
        handle.join().expect("server join");
        assert!(error.contains("did not return two embeddings"));
    }
}
