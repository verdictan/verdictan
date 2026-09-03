// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan token exchange-code` — redeem a consented OAuth authorization code for a
//! one-time-reveal API token.
//!
//! the code-minting `GET /v1/oauth/authorize` is retired.
//! The `--code` redeemed here is a one-time authorization code minted ONLY by
//! the authenticated, CSRF-protected consent flow
//! (`POST /v1/oauth/authorize/preview` + `POST /v1/oauth/authorize/decision`),
//! obtained by the user through the browser console consent surface which
//! redirects the code back to the CLI's `--redirect-uri` localhost callback.
//! The API stores that code HASHED at rest and redeems it single-use here.
//!
//! This command performs only the final redemption POST; it never mints a code
//! and never calls the retired GET. Driving the browser to the console consent
//! surface and capturing the localhost callback is the deferred console follow
//! slice (`console/src/app/oauth/authorize/page.tsx`), because the CLI cannot
//! self-authenticate the cookie+CSRF-protected `POST /decision`.

use std::time::Duration;

use clap::{Args, ValueEnum};
use serde::Serialize;

use crate::{
    config::{Config, ConfigInputs},
    error::CliError,
    output::json::print_json,
};

#[derive(Debug, Clone, ValueEnum)]
pub enum TokenExchangeScope {
    Org,
    Team,
    Project,
}

impl TokenExchangeScope {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Org => "org",
            Self::Team => "team",
            Self::Project => "project",
        }
    }
}

#[derive(Debug, Args)]
pub struct TokenExchangeCodeArgs {
    #[arg(long)]
    pub code: String,

    #[arg(long)]
    pub code_verifier: String,

    #[arg(long)]
    pub client_id: String,

    #[arg(long)]
    pub redirect_uri: String,

    #[arg(long)]
    pub token_name: String,

    #[arg(long, default_value = "general")]
    pub purpose: String,

    #[arg(long, value_enum)]
    pub scope: TokenExchangeScope,

    #[arg(long)]
    pub team_id: Option<String>,

    #[arg(long = "project-id")]
    pub project_ids: Vec<String>,

    #[arg(long)]
    pub gateway_id: Option<String>,

    #[arg(long)]
    pub budget_id: Option<String>,

    #[arg(long)]
    pub provider: Option<String>,

    #[arg(long = "model-filter")]
    pub model_filter: Vec<String>,

    #[arg(long)]
    pub rate_limit_rpm: Option<i32>,

    #[arg(long)]
    pub rate_limit_tpm: Option<i32>,

    #[arg(long)]
    pub max_budget: Option<f64>,

    #[arg(long)]
    pub currency: Option<String>,

    #[arg(long)]
    pub json: bool,

    #[arg(long)]
    pub config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub api_url: Option<String>,

    #[arg(long, default_value = "default")]
    pub profile: String,
}

#[derive(Debug, Serialize)]
pub struct TokenExchangeRequest {
    pub code: String,
    pub code_verifier: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub token_name: String,
    pub purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_bindings: Option<TokenExchangeRuntimeBindings>,
    pub scope_metadata: TokenExchangeScopeMetadata,
}

#[derive(Debug, Serialize)]
pub struct TokenExchangeRuntimeBindings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub model_filter: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_rpm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_tpm: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_budget: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenExchangeScopeMetadata {
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub project_ids: Vec<String>,
}
pub(crate) async fn run_async(args: TokenExchangeCodeArgs) -> Result<(), CliError> {
    let config = Config::resolve(ConfigInputs {
        api_url_flag: args.api_url.clone(),
        api_token_flag: None,
        config_path: args.config.clone(),
        profile_flag: Some(args.profile.clone()),
        region_flag: None,
    })?;

    let request = build_request(&args)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| CliError::internal(format!("failed to build http client: {error}")))?;

    let response = client
        .post(format!(
            "{}/v1/tokens/exchange-code",
            config.api_url.trim_end_matches('/')
        ))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            reqwest::header::USER_AGENT,
            concat!("verdictan-cli/", env!("CARGO_PKG_VERSION")),
        )
        .json(&request)
        .send()
        .await
        .map_err(map_network_error)?;

    let status = response.status();
    let body = response.bytes().await.map_err(map_network_error)?;

    if !status.is_success() {
        let message = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
            });
        return Err(map_http_error(status, message));
    }

    let response: serde_json::Value = serde_json::from_slice(&body).map_err(|error| {
        CliError::internal(format!("failed to decode token exchange response: {error}"))
    })?;
    let token_value = response
        .get("token_value")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| CliError::internal("token exchange response missing token_value"))?;

    if args.json {
        return print_json(&response);
    }

    println!("{token_value}");
    Ok(())
}

pub fn build_request_public(
    args: &TokenExchangeCodeArgs,
) -> Result<TokenExchangeRequest, CliError> {
    build_request(args)
}

fn build_request(args: &TokenExchangeCodeArgs) -> Result<TokenExchangeRequest, CliError> {
    let scope_metadata = match args.scope {
        TokenExchangeScope::Org => {
            if args.team_id.is_some() || !args.project_ids.is_empty() {
                return Err(CliError::user(
                    "org scope cannot be combined with --team-id or --project-id",
                ));
            }
            TokenExchangeScopeMetadata {
                scope: args.scope.as_str().to_string(),
                team_id: None,
                project_ids: Vec::new(),
            }
        }
        TokenExchangeScope::Team => {
            let Some(team_id) = args
                .team_id
                .clone()
                .filter(|value| !value.trim().is_empty())
            else {
                return Err(CliError::user("team scope requires --team-id"));
            };
            if !args.project_ids.is_empty() {
                return Err(CliError::user(
                    "team scope cannot be combined with --project-id",
                ));
            }
            TokenExchangeScopeMetadata {
                scope: args.scope.as_str().to_string(),
                team_id: Some(team_id),
                project_ids: Vec::new(),
            }
        }
        TokenExchangeScope::Project => {
            if args.team_id.is_some() {
                return Err(CliError::user(
                    "project scope cannot be combined with --team-id",
                ));
            }
            if args.project_ids.is_empty() {
                return Err(CliError::user(
                    "project scope requires at least one --project-id",
                ));
            }
            TokenExchangeScopeMetadata {
                scope: args.scope.as_str().to_string(),
                team_id: None,
                project_ids: args.project_ids.clone(),
            }
        }
    };

    let runtime_bindings = TokenExchangeRuntimeBindings {
        gateway_id: args.gateway_id.clone(),
        team_id: args.team_id.clone(),
        budget_id: args.budget_id.clone(),
        provider: args.provider.clone(),
        model_filter: args.model_filter.clone(),
        rate_limit_rpm: args.rate_limit_rpm,
        rate_limit_tpm: args.rate_limit_tpm,
        max_budget: args.max_budget,
        currency: args.currency.clone(),
    };
    let runtime_bindings = if runtime_bindings.gateway_id.is_none()
        && runtime_bindings.team_id.is_none()
        && runtime_bindings.budget_id.is_none()
        && runtime_bindings.provider.is_none()
        && runtime_bindings.model_filter.is_empty()
        && runtime_bindings.rate_limit_rpm.is_none()
        && runtime_bindings.rate_limit_tpm.is_none()
        && runtime_bindings.max_budget.is_none()
        && runtime_bindings.currency.is_none()
    {
        None
    } else {
        Some(runtime_bindings)
    };

    Ok(TokenExchangeRequest {
        code: args.code.trim().to_string(),
        code_verifier: args.code_verifier.trim().to_string(),
        client_id: args.client_id.trim().to_string(),
        redirect_uri: args.redirect_uri.trim().to_string(),
        token_name: args.token_name.trim().to_string(),
        purpose: args.purpose.trim().to_string(),
        runtime_bindings,
        scope_metadata,
    })
}

fn map_http_error(status: reqwest::StatusCode, message: Option<String>) -> CliError {
    let message =
        message.unwrap_or_else(|| format!("request failed with status {}", status.as_u16()));
    match status {
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
            CliError::auth(message).with_http_status(status.as_u16())
        }
        reqwest::StatusCode::BAD_REQUEST
        | reqwest::StatusCode::CONFLICT
        | reqwest::StatusCode::UNPROCESSABLE_ENTITY => {
            CliError::user(message).with_http_status(status.as_u16())
        }
        _ => CliError::network(message).with_http_status(status.as_u16()),
    }
}

fn map_network_error(error: reqwest::Error) -> CliError {
    if error.is_timeout() {
        return CliError::network("request timed out");
    }
    if error.is_connect() {
        return CliError::network("failed to connect to API");
    }
    CliError::network(format!("http error: {error}"))
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

    #[test]
    fn build_request_requires_team_id_for_team_scope() {
        let error = build_request(&TokenExchangeCodeArgs {
            code: "code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://console.verdictan.com/callback".to_string(),
            token_name: "CLI Access Key".to_string(),
            purpose: "general".to_string(),
            scope: TokenExchangeScope::Team,
            team_id: None,
            project_ids: Vec::new(),
            gateway_id: None,
            budget_id: None,
            provider: None,
            model_filter: Vec::new(),
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            currency: None,
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("team scope requires --team-id"));
    }

    #[test]
    fn build_request_omits_empty_runtime_bindings() {
        let request = build_request(&TokenExchangeCodeArgs {
            code: "code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://console.verdictan.com/callback".to_string(),
            token_name: "CLI Access Key".to_string(),
            purpose: "general".to_string(),
            scope: TokenExchangeScope::Org,
            team_id: None,
            project_ids: Vec::new(),
            gateway_id: None,
            budget_id: None,
            provider: None,
            model_filter: Vec::new(),
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            currency: None,
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .expect("request");

        assert!(request.runtime_bindings.is_none());
        assert_eq!(request.scope_metadata.scope, "org");
    }

    #[test]
    fn build_request_org_scope_rejects_team_id() {
        let error = build_request(&TokenExchangeCodeArgs {
            code: "code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            token_name: "test".to_string(),
            purpose: "general".to_string(),
            scope: TokenExchangeScope::Org,
            team_id: Some("team-1".to_string()),
            project_ids: Vec::new(),
            gateway_id: None,
            budget_id: None,
            provider: None,
            model_filter: Vec::new(),
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            currency: None,
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("org scope cannot be combined with --team-id"));
    }

    #[test]
    fn build_request_org_scope_rejects_project_ids() {
        let error = build_request(&TokenExchangeCodeArgs {
            code: "code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            token_name: "test".to_string(),
            purpose: "general".to_string(),
            scope: TokenExchangeScope::Org,
            team_id: None,
            project_ids: vec!["proj-1".to_string()],
            gateway_id: None,
            budget_id: None,
            provider: None,
            model_filter: Vec::new(),
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            currency: None,
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("org scope cannot be combined with"));
    }

    #[test]
    fn build_request_team_scope_rejects_project_ids() {
        let error = build_request(&TokenExchangeCodeArgs {
            code: "code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            token_name: "test".to_string(),
            purpose: "general".to_string(),
            scope: TokenExchangeScope::Team,
            team_id: Some("team-1".to_string()),
            project_ids: vec!["proj-1".to_string()],
            gateway_id: None,
            budget_id: None,
            provider: None,
            model_filter: Vec::new(),
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            currency: None,
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("team scope cannot be combined with --project-id"));
    }

    #[test]
    fn build_request_team_scope_rejects_empty_team_id() {
        let error = build_request(&TokenExchangeCodeArgs {
            code: "code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            token_name: "test".to_string(),
            purpose: "general".to_string(),
            scope: TokenExchangeScope::Team,
            team_id: Some("  ".to_string()),
            project_ids: Vec::new(),
            gateway_id: None,
            budget_id: None,
            provider: None,
            model_filter: Vec::new(),
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            currency: None,
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("team scope requires --team-id"));
    }

    #[test]
    fn build_request_project_scope_requires_project_ids() {
        let error = build_request(&TokenExchangeCodeArgs {
            code: "code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            token_name: "test".to_string(),
            purpose: "general".to_string(),
            scope: TokenExchangeScope::Project,
            team_id: None,
            project_ids: Vec::new(),
            gateway_id: None,
            budget_id: None,
            provider: None,
            model_filter: Vec::new(),
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            currency: None,
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("project scope requires at least one --project-id"));
    }

    #[test]
    fn build_request_project_scope_rejects_team_id() {
        let error = build_request(&TokenExchangeCodeArgs {
            code: "code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            token_name: "test".to_string(),
            purpose: "general".to_string(),
            scope: TokenExchangeScope::Project,
            team_id: Some("team-1".to_string()),
            project_ids: vec!["proj-1".to_string()],
            gateway_id: None,
            budget_id: None,
            provider: None,
            model_filter: Vec::new(),
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            currency: None,
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("project scope cannot be combined with --team-id"));
    }

    #[test]
    fn build_request_includes_runtime_bindings_when_present() {
        let request = build_request(&TokenExchangeCodeArgs {
            code: " code-1 ".to_string(),
            code_verifier: " verifier-1 ".to_string(),
            client_id: " client-1 ".to_string(),
            redirect_uri: " https://example.com/cb ".to_string(),
            token_name: " Token Name ".to_string(),
            purpose: " integration ".to_string(),
            scope: TokenExchangeScope::Org,
            team_id: None,
            project_ids: Vec::new(),
            gateway_id: Some("gw-1".to_string()),
            budget_id: Some("budget-1".to_string()),
            provider: Some("openai".to_string()),
            model_filter: vec!["gpt-4o".to_string()],
            rate_limit_rpm: Some(60),
            rate_limit_tpm: Some(10000),
            max_budget: Some(50.0),
            currency: Some("EUR".to_string()),
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .expect("valid request");

        assert_eq!(request.code, "code-1");
        assert_eq!(request.code_verifier, "verifier-1");
        assert_eq!(request.client_id, "client-1");
        assert_eq!(request.redirect_uri, "https://example.com/cb");
        assert_eq!(request.token_name, "Token Name");
        assert_eq!(request.purpose, "integration");
        let bindings = request.runtime_bindings.unwrap();
        assert_eq!(bindings.gateway_id.as_deref(), Some("gw-1"));
        assert_eq!(bindings.budget_id.as_deref(), Some("budget-1"));
        assert_eq!(bindings.provider.as_deref(), Some("openai"));
        assert_eq!(bindings.model_filter, vec!["gpt-4o"]);
        assert_eq!(bindings.rate_limit_rpm, Some(60));
        assert_eq!(bindings.rate_limit_tpm, Some(10000));
        assert_eq!(bindings.max_budget, Some(50.0));
        assert_eq!(bindings.currency.as_deref(), Some("EUR"));
    }

    #[test]
    fn build_request_team_scope_valid() {
        let request = build_request(&TokenExchangeCodeArgs {
            code: "code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            token_name: "test".to_string(),
            purpose: "general".to_string(),
            scope: TokenExchangeScope::Team,
            team_id: Some("team-alpha".to_string()),
            project_ids: Vec::new(),
            gateway_id: None,
            budget_id: None,
            provider: None,
            model_filter: Vec::new(),
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            currency: None,
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .expect("valid team scope request");

        assert_eq!(request.scope_metadata.scope, "team");
        assert_eq!(
            request.scope_metadata.team_id.as_deref(),
            Some("team-alpha")
        );
    }

    #[test]
    fn build_request_project_scope_valid() {
        let request = build_request(&TokenExchangeCodeArgs {
            code: "code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            token_name: "test".to_string(),
            purpose: "general".to_string(),
            scope: TokenExchangeScope::Project,
            team_id: None,
            project_ids: vec!["proj-1".to_string(), "proj-2".to_string()],
            gateway_id: None,
            budget_id: None,
            provider: None,
            model_filter: Vec::new(),
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            currency: None,
            json: false,
            config: None,
            api_url: None,
            profile: "default".to_string(),
        })
        .expect("valid project scope request");

        assert_eq!(request.scope_metadata.scope, "project");
        assert_eq!(request.scope_metadata.project_ids, vec!["proj-1", "proj-2"]);
    }

    #[test]
    fn map_http_error_categorizes_status_codes() {
        let auth_err = map_http_error(reqwest::StatusCode::UNAUTHORIZED, None);
        assert!(auth_err.to_string().contains("401"));

        let forbidden_err =
            map_http_error(reqwest::StatusCode::FORBIDDEN, Some("denied".to_string()));
        assert!(forbidden_err.to_string().contains("denied"));

        let bad_req_err = map_http_error(
            reqwest::StatusCode::BAD_REQUEST,
            Some("bad input".to_string()),
        );
        assert!(bad_req_err.to_string().contains("bad input"));

        let conflict_err = map_http_error(reqwest::StatusCode::CONFLICT, None);
        assert!(conflict_err.to_string().contains("409"));

        let unprocessable_err = map_http_error(reqwest::StatusCode::UNPROCESSABLE_ENTITY, None);
        assert!(unprocessable_err.to_string().contains("422"));

        let server_err = map_http_error(reqwest::StatusCode::INTERNAL_SERVER_ERROR, None);
        assert!(server_err.to_string().contains("500"));
    }

    #[test]
    fn token_exchange_scope_as_str() {
        assert_eq!(TokenExchangeScope::Org.as_str(), "org");
        assert_eq!(TokenExchangeScope::Team.as_str(), "team");
        assert_eq!(TokenExchangeScope::Project.as_str(), "project");
    }

    #[test]
    fn token_exchange_request_serializes_correctly() {
        let request = TokenExchangeRequest {
            code: "auth-code".to_string(),
            code_verifier: "verifier".to_string(),
            client_id: "client-id".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            token_name: "My Token".to_string(),
            purpose: "general".to_string(),
            runtime_bindings: None,
            scope_metadata: TokenExchangeScopeMetadata {
                scope: "org".to_string(),
                team_id: None,
                project_ids: Vec::new(),
            },
        };
        let json = serde_json::to_value(&request).expect("serialize request");
        assert_eq!(json["code"], "auth-code");
        assert_eq!(json["token_name"], "My Token");
        assert!(json.get("runtime_bindings").is_none());
        assert_eq!(json["scope_metadata"]["scope"], "org");
    }

    #[test]
    fn token_exchange_request_serializes_with_bindings() {
        let request = TokenExchangeRequest {
            code: "c".to_string(),
            code_verifier: "v".to_string(),
            client_id: "cl".to_string(),
            redirect_uri: "https://x.com/cb".to_string(),
            token_name: "t".to_string(),
            purpose: "integration".to_string(),
            runtime_bindings: Some(TokenExchangeRuntimeBindings {
                gateway_id: Some("gw-1".to_string()),
                team_id: None,
                budget_id: None,
                provider: Some("anthropic".to_string()),
                model_filter: vec!["claude-4".to_string()],
                rate_limit_rpm: Some(100),
                rate_limit_tpm: None,
                max_budget: Some(25.0),
                currency: Some("USD".to_string()),
            }),
            scope_metadata: TokenExchangeScopeMetadata {
                scope: "team".to_string(),
                team_id: Some("t-1".to_string()),
                project_ids: Vec::new(),
            },
        };
        let json = serde_json::to_value(&request).expect("serialize with bindings");
        assert_eq!(json["runtime_bindings"]["gateway_id"], "gw-1");
        assert_eq!(json["runtime_bindings"]["provider"], "anthropic");
        assert_eq!(json["runtime_bindings"]["model_filter"][0], "claude-4");
        assert_eq!(json["runtime_bindings"]["rate_limit_rpm"], 100);
        assert_eq!(json["runtime_bindings"]["max_budget"], 25.0);
        assert_eq!(json["scope_metadata"]["team_id"], "t-1");
    }
}
