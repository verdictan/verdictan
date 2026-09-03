// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! RS256 fixtures for gateway machine-JWT tests.
//!
//! Shared by `gateway::jwt_auth` and by tests that must present a signed peer
//! token to a [`crate::gateway::jwt_auth::GatewayAuthClient`], so all lanes
//! verify against one key pair. Keys are generated at test runtime so no PEM
//! material is stored in the repository.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{routing::get, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

use crate::gateway::jwt_auth::{MachineClaims, OneOrMany, EXPECTED_ISSUER};

use super::test_server::SpawnedServer;

pub const TEST_RSA_KID: &str = "kid-rs256-test";

struct TestRsaFixture {
    private_pem: String,
    jwks: serde_json::Value,
}

fn test_rsa_fixture() -> &'static TestRsaFixture {
    static FIXTURE: OnceLock<TestRsaFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate rsa key pair");
        let private_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode private key")
            .to_string();
        let public_key = RsaPublicKey::from(&private_key);
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": TEST_RSA_KID,
                "alg": "RS256",
                "use": "sig",
                "n": n,
                "e": e
            }]
        });
        TestRsaFixture { private_pem, jwks }
    })
}

pub(crate) fn test_jwks_payload() -> serde_json::Value {
    test_rsa_fixture().jwks.clone()
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time drift")
        .as_secs() as i64
}

pub fn machine_claims_for_test(aud: OneOrMany, exp: i64, org_id: &str, jti: &str) -> MachineClaims {
    MachineClaims {
        iss: EXPECTED_ISSUER.to_string(),
        sub: "gateway:test".to_string(),
        aud,
        exp,
        iat: unix_now() - 10,
        jti: jti.to_string(),
        org_id: org_id.to_string(),
        principal_type: "gateway".to_string(),
        actor_class: "machine".to_string(),
        scope: "gateway".to_string(),
        gateway_id: Some("gateway-1".to_string()),
        azp: "verdictan-cli".to_string(),
        rev_check: Some("online".to_string()),
        region: Some("eu-west-1".to_string()),
    }
}

pub fn sign_machine_token(claims: &MachineClaims, kid: Option<&str>) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(ToOwned::to_owned);
    let pem = test_rsa_fixture().private_pem.as_bytes();
    let key = EncodingKey::from_rsa_pem(pem).expect("rsa key");
    encode(&header, claims, &key).expect("sign token")
}

/// Serve the fixture JWKS and an empty revocation list on a loopback port.
pub async fn start_jwks_server() -> SpawnedServer {
    let jwks = test_jwks_payload();
    let app = Router::new()
        .route(
            "/v1/jwt/jwks",
            get(move || {
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        )
        .route(
            "/v1/jwt/revocations",
            get(|| async {
                Json(serde_json::json!({
                    "revoked_jtis": [],
                    "server_time": 0
                }))
            }),
        );
    SpawnedServer::bind(app).await
}
