// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde::{Deserialize, Serialize};

use crate::error::CliError;
use crate::i18n;

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: String,
    pub org_id: String,
    pub org_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_slug: Option<String>,
    pub project_id: String,
    pub role: String,
    pub authz_version: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub team_ids: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Wire format returned by `POST /v1/auth/login`.
#[derive(Debug, Deserialize)]
struct ApiLoginResponse {
    session: ApiSession,
    organization: ApiOrganization,
    user: ApiUser,
    project: ApiProject,
    #[serde(default)]
    teams: ApiTeams,
    #[serde(default)]
    authorization: ApiAuthorization,
}

#[derive(Debug, Deserialize)]
struct ApiSession {
    token: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct ApiOrganization {
    id: String,
    name: String,
    #[serde(default)]
    slug: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiUser {
    id: String,
    email: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct ApiProject {
    id: String,
}

#[derive(Debug, Default, Deserialize)]
struct ApiTeams {
    #[serde(default)]
    ids: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ApiAuthorization {
    #[serde(default)]
    role: String,
    #[serde(default)]
    authz_version: i64,
}

impl From<ApiLoginResponse> for LoginResponse {
    fn from(api: ApiLoginResponse) -> Self {
        Self {
            token: api.session.token,
            expires_at: api.session.expires_at,
            org_id: api.organization.id,
            org_name: api.organization.name,
            org_slug: api.organization.slug,
            project_id: api.project.id,
            role: api.authorization.role,
            authz_version: api.authorization.authz_version,
            user_id: Some(api.user.id),
            email: Some(api.user.email),
            display_name: Some(api.user.display_name),
            team_ids: api.teams.ids,
            capabilities: Vec::new(),
        }
    }
}

pub async fn login_async(
    base_url: &str,
    request: &LoginRequest,
) -> Result<LoginResponse, CliError> {
    let response = reqwest::Client::new()
        .post(join_url(base_url, "/v1/auth/login"))
        .json(request)
        .send()
        .await
        .map_err(map_reqwest_error)?;

    let status = response.status();
    if !status.is_success() {
        return Err(map_http_status(status));
    }

    let api_response = response
        .json::<ApiLoginResponse>()
        .await
        .map_err(map_reqwest_error)?;

    Ok(LoginResponse::from(api_response))
}

fn join_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

fn map_http_status(status: reqwest::StatusCode) -> CliError {
    let locale = i18n::global();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return CliError::auth(i18n::t(locale, "auth.login_failed_401"));
    }
    if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        return CliError::user(i18n::t(locale, "user.login_validation_failed_422"));
    }
    CliError::network(i18n::t_fmt(
        locale,
        "network.login_request_failed_status",
        &[&status.as_u16().to_string()],
    ))
}

fn map_reqwest_error(error: reqwest::Error) -> CliError {
    let locale = i18n::global();
    if error.is_timeout() {
        return CliError::network(i18n::t(locale, "network.request_timed_out"));
    }
    if error.is_connect() {
        return CliError::network(i18n::t(locale, "network.failed_to_connect_api"));
    }
    CliError::network(i18n::t_fmt(
        locale,
        "network.http_error",
        &[&error.to_string()],
    ))
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
    fn join_url_trims_duplicate_slashes() {
        assert_eq!(
            join_url("https://api.verdictan.com/", "/v1/auth/login"),
            "https://api.verdictan.com/v1/auth/login"
        );
        assert_eq!(
            join_url("https://api.verdictan.com", "v1/auth/login"),
            "https://api.verdictan.com/v1/auth/login"
        );
    }

    #[test]
    fn api_login_response_maps_to_login_response() {
        let response = ApiLoginResponse {
            session: ApiSession {
                token: "jwt_token".to_string(),
                expires_at: "2026-07-01T00:00:00Z".to_string(),
            },
            organization: ApiOrganization {
                id: "org_123".to_string(),
                name: "Acme".to_string(),
                slug: Some("acme".to_string()),
            },
            user: ApiUser {
                id: "user_123".to_string(),
                email: "user@example.com".to_string(),
                display_name: "User".to_string(),
            },
            project: ApiProject {
                id: "project_123".to_string(),
            },
            teams: ApiTeams {
                ids: vec!["team_a".to_string(), "team_b".to_string()],
            },
            authorization: ApiAuthorization {
                role: "admin".to_string(),
                authz_version: 9,
            },
        };

        let mapped = LoginResponse::from(response);
        assert_eq!(mapped.token, "jwt_token");
        assert_eq!(mapped.org_id, "org_123");
        assert_eq!(mapped.org_name, "Acme");
        assert_eq!(mapped.org_slug.as_deref(), Some("acme"));
        assert_eq!(mapped.project_id, "project_123");
        assert_eq!(mapped.role, "admin");
        assert_eq!(mapped.authz_version, 9);
        assert_eq!(mapped.user_id.as_deref(), Some("user_123"));
        assert_eq!(mapped.email.as_deref(), Some("user@example.com"));
        assert_eq!(mapped.display_name.as_deref(), Some("User"));
        assert_eq!(mapped.team_ids, vec!["team_a", "team_b"]);
        assert!(mapped.capabilities.is_empty());
    }

    #[test]
    fn map_http_status_uses_expected_error_kinds() {
        let unauthorized = map_http_status(reqwest::StatusCode::UNAUTHORIZED);
        assert_eq!(unauthorized.error_code(), "cli.auth_failed");

        let validation = map_http_status(reqwest::StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(validation.error_code(), "cli.config_invalid");

        let server = map_http_status(reqwest::StatusCode::BAD_GATEWAY);
        assert_eq!(server.error_code(), "cli.network_error");
    }
}
