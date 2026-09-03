// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Identity proof and resolution for the gateway.
//!
//! Supports identity modes for per-request caller attribution:
//! - **ApiToken**: identity bound to an authenticated API token record.
//!   The token's own `user_id`/`team_id` fields are authoritative.
//! - **SignedAssertion**: caller identity from a JWKS-verified JWT Bearer token.
//!   Provides cryptographic proof of caller identity.
//!
//! [`AuthenticatedRequestIdentity`] and [`PolicyIdentityContext`] are populated
//! only from API `validate_token` / machine-token validation claims or a
//! verified signed assertion — never from spoofable request headers.

use std::collections::BTreeSet;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How caller identity was established for this request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProofMethod {
    /// Legacy unverified header-derived identity label retained for event ingest
    /// compatibility and default attribution when no token identity is present.
    HeaderSoft,
    /// Identity bound to an authenticated API token record.
    ApiToken,
    /// Identity derived from the gateway's own runtime API token (`VERDICTAN_API_TOKEN`).
    RuntimeToken,
    /// Identity from a JWKS-verified JWT assertion.
    SignedAssertion,
}

impl IdentityProofMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HeaderSoft => "header_soft",
            Self::ApiToken => "api_token",
            Self::RuntimeToken => "runtime_token",
            Self::SignedAssertion => "signed_assertion",
        }
    }
}

/// Authentication strength asserted by a verified identity source.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAssuranceLevel {
    Token,
    SingleFactor,
    MultiFactor,
    PhishingResistant,
}

/// Wire claims returned by the API's authoritative token-validation contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticatedIdentityClaims {
    pub proof_method: IdentityProofMethod,
    pub issuer: String,
    pub subject: String,
    pub credential_id: String,
    pub org_id: String,
    #[serde(default)]
    pub team_ids: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub assurance_level: IdentityAssuranceLevel,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Identity claims that have passed an authoritative authentication proof.
///
/// Callers cannot construct this type with a struct literal. Gateway code may
/// create it only from a successful API token-validation response or from a
/// signature-verified assertion.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthenticatedRequestIdentity {
    proof_method: IdentityProofMethod,
    issuer: String,
    subject: String,
    credential_id: String,
    org_id: String,
    team_ids: Vec<String>,
    roles: Vec<String>,
    scopes: Vec<String>,
    assurance_level: IdentityAssuranceLevel,
    expires_at: Option<DateTime<Utc>>,
}

impl AuthenticatedRequestIdentity {
    /// Build typed identity only from an authoritative verification result.
    ///
    /// Accepted proof methods:
    /// - [`IdentityProofMethod::ApiToken`] — API `validate_token` claims
    /// - [`IdentityProofMethod::RuntimeToken`] — machine/runtime token validation
    /// - [`IdentityProofMethod::SignedAssertion`] — JWKS-verified JWT assertion
    ///
    /// [`IdentityProofMethod::HeaderSoft`] and any other unverified source are
    /// rejected. Spoofable request headers must never reach this constructor.
    pub fn from_validated_claims(claims: AuthenticatedIdentityClaims) -> anyhow::Result<Self> {
        match claims.proof_method {
            IdentityProofMethod::ApiToken
            | IdentityProofMethod::RuntimeToken
            | IdentityProofMethod::SignedAssertion => {}
            IdentityProofMethod::HeaderSoft => {
                return Err(anyhow!(
                    "header-soft claims cannot create authenticated request identity"
                ));
            }
        }
        let issuer = required_claim("issuer", claims.issuer)?;
        let subject = required_claim("subject", claims.subject)?;
        let credential_id = required_claim("credential_id", claims.credential_id)?;
        let org_id = required_claim("org_id", claims.org_id)?;
        if claims.expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
            return Err(anyhow!("authenticated identity proof is expired"));
        }

        Ok(Self {
            proof_method: claims.proof_method,
            issuer,
            subject,
            credential_id,
            org_id,
            team_ids: canonical_claim_set(claims.team_ids),
            roles: canonical_claim_set(claims.roles),
            scopes: canonical_claim_set(claims.scopes),
            assurance_level: claims.assurance_level,
            expires_at: claims.expires_at,
        })
    }

    pub fn proof_method(&self) -> IdentityProofMethod {
        self.proof_method
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    pub fn org_id(&self) -> &str {
        &self.org_id
    }

    pub fn team_ids(&self) -> &[String] {
        &self.team_ids
    }

    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn assurance_level(&self) -> IdentityAssuranceLevel {
        self.assurance_level
    }

    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// Policy-facing projection of this verified identity.
    pub fn to_policy_identity_context(&self) -> PolicyIdentityContext {
        PolicyIdentityContext::from(self)
    }
}

/// Policy-facing projection of an authenticated request identity.
///
/// Constructed only from [`AuthenticatedRequestIdentity`], never from
/// spoofable request headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIdentityContext {
    pub proof_method: IdentityProofMethod,
    pub issuer: String,
    pub subject: String,
    pub credential_id: String,
    pub org_id: String,
    pub team_ids: Vec<String>,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
    pub assurance_level: IdentityAssuranceLevel,
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<&AuthenticatedRequestIdentity> for PolicyIdentityContext {
    fn from(identity: &AuthenticatedRequestIdentity) -> Self {
        Self {
            proof_method: identity.proof_method(),
            issuer: identity.issuer().to_string(),
            subject: identity.subject().to_string(),
            credential_id: identity.credential_id().to_string(),
            org_id: identity.org_id().to_string(),
            team_ids: identity.team_ids().to_vec(),
            roles: identity.roles().to_vec(),
            scopes: identity.scopes().to_vec(),
            assurance_level: identity.assurance_level(),
            expires_at: identity.expires_at(),
        }
    }
}

fn required_claim(name: &str, value: String) -> anyhow::Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("authenticated identity is missing {name}"));
    }
    Ok(value.to_string())
}

fn canonical_claim_set(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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
    fn validated_claims_reject_unverified_and_expired_identity() {
        let base = AuthenticatedIdentityClaims {
            proof_method: IdentityProofMethod::ApiToken,
            issuer: "verdictan-api".to_string(),
            subject: "user-1".to_string(),
            credential_id: "token-1".to_string(),
            org_id: "org-1".to_string(),
            team_ids: vec!["team-1".to_string()],
            roles: vec!["member".to_string()],
            scopes: vec!["events:read".to_string()],
            assurance_level: IdentityAssuranceLevel::Token,
            expires_at: Some(Utc::now() + chrono::Duration::minutes(5)),
        };

        let runtime = AuthenticatedIdentityClaims {
            proof_method: IdentityProofMethod::RuntimeToken,
            ..base.clone()
        };
        assert!(AuthenticatedRequestIdentity::from_validated_claims(runtime).is_ok());

        let header_soft = AuthenticatedIdentityClaims {
            proof_method: IdentityProofMethod::HeaderSoft,
            ..base.clone()
        };
        assert!(AuthenticatedRequestIdentity::from_validated_claims(header_soft).is_err());

        let expired = AuthenticatedIdentityClaims {
            expires_at: Some(Utc::now() - chrono::Duration::seconds(1)),
            ..base.clone()
        };
        assert!(AuthenticatedRequestIdentity::from_validated_claims(expired).is_err());

        let missing_org = AuthenticatedIdentityClaims {
            org_id: "   ".to_string(),
            ..base
        };
        assert!(AuthenticatedRequestIdentity::from_validated_claims(missing_org).is_err());
    }

    #[test]
    fn validated_claims_canonicalize_sets_and_project_policy_identity() {
        let identity =
            AuthenticatedRequestIdentity::from_validated_claims(AuthenticatedIdentityClaims {
                proof_method: IdentityProofMethod::ApiToken,
                issuer: "verdictan-api".to_string(),
                subject: "user-1".to_string(),
                credential_id: "token-1".to_string(),
                org_id: "org-1".to_string(),
                team_ids: vec![
                    " team-b ".to_string(),
                    "team-a".to_string(),
                    "team-a".to_string(),
                    "".to_string(),
                ],
                roles: vec!["reviewer".to_string(), "operator".to_string()],
                scopes: vec!["events:write".to_string(), "events:read".to_string()],
                assurance_level: IdentityAssuranceLevel::Token,
                expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            })
            .expect("validated claims");

        assert_eq!(identity.team_ids(), ["team-a", "team-b"]);
        assert_eq!(identity.roles(), ["operator", "reviewer"]);
        assert_eq!(identity.scopes(), ["events:read", "events:write"]);

        let policy = PolicyIdentityContext::from(&identity);
        assert_eq!(policy.proof_method, IdentityProofMethod::ApiToken);
        assert_eq!(policy.issuer, "verdictan-api");
        assert_eq!(policy.subject, "user-1");
        assert_eq!(policy.credential_id, "token-1");
        assert_eq!(policy.org_id, "org-1");
        assert_eq!(policy.team_ids, ["team-a", "team-b"]);
        assert_eq!(policy.roles, ["operator", "reviewer"]);
        assert_eq!(policy.scopes, ["events:read", "events:write"]);
        assert_eq!(policy.assurance_level, IdentityAssuranceLevel::Token);
        assert!(policy.expires_at.is_some());
    }
}
