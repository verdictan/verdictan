// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

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
use axum::http::{HeaderMap, HeaderValue};
use chrono::Duration;

fn publication(
    hostname: &str,
    state: &str,
) -> crate::runtime::ConnectedGatewayPublicationDescriptor {
    let active_revision_readiness_state = if state.eq_ignore_ascii_case("draining") {
        "draining"
    } else {
        "active"
    };
    crate::runtime::ConnectedGatewayPublicationDescriptor {
        family_key: "global".to_string(),
        publication_key: "pub_123".to_string(),
        published_hostname: Some(hostname.to_string()),
        publication_state: state.to_string(),
        active_revision_id: Some("rev-active".to_string()),
        active_revision_readiness_state: Some(active_revision_readiness_state.to_string()),
        active_revision_auth_digest: Some("auth-digest-active".to_string()),
        active_revision_policy_digest: Some("policy-digest-active".to_string()),
        active_revision_pool_membership_issue: None,
        locality_mode: "region_pinned".to_string(),
        serving_fleet_class: "managed".to_string(),
        primary_region_group_key: None,
    }
}

fn fresh_read_model(
    publication_catalog: Vec<crate::runtime::ConnectedGatewayPublicationDescriptor>,
) -> ConnectedGatewayReadModelSnapshot {
    let routing_compatibility = publication_catalog
        .iter()
        .map(
            |publication| crate::runtime::ConnectedGatewayRoutingCompatibilityDescriptor {
                publication_key: publication.publication_key.clone(),
                active_revision_id: publication.active_revision_id.clone(),
                primary_region_group_key: publication.primary_region_group_key.clone(),
                readiness_state: publication.active_revision_readiness_state.clone(),
                compatibility_digest: None,
                auth_digest: publication.active_revision_auth_digest.clone(),
                policy_digest: publication.active_revision_policy_digest.clone(),
                runtime_manifest_digest: None,
                active_revision_pool_membership_issue: publication
                    .active_revision_pool_membership_issue
                    .clone(),
            },
        )
        .collect::<Vec<_>>();
    let publication_catalog = publication_catalog
        .into_iter()
        .map(
            |publication| crate::runtime::ConnectedGatewayPublicationCatalogDescriptor {
                family_key: publication.family_key,
                publication_key: publication.publication_key,
                published_hostname: publication.published_hostname,
                publication_state: publication.publication_state,
                active_revision_id: publication.active_revision_id,
                locality_mode: publication.locality_mode,
                serving_fleet_class: publication.serving_fleet_class,
                agent_id: None,
            },
        )
        .collect::<Vec<_>>();
    let publication_catalog_shards =
        build_managed_public_endpoint_catalog_shards(&publication_catalog);
    let routing_compatibility_index = build_routing_compatibility_index(&routing_compatibility);
    ConnectedGatewayReadModelSnapshot {
        region_key: Some("eu-sovereign".to_string()),
        publication_catalog,
        publication_catalog_shards,
        publication_catalog_last_successful_refresh_at: Some(Utc::now()),
        publication_catalog_last_refresh_error: None,
        routing_compatibility,
        routing_compatibility_index,
        routing_compatibility_last_successful_refresh_at: Some(Utc::now()),
        routing_compatibility_last_refresh_error: None,
        auth_verification_material: None,
        auth_verification_material_last_successful_refresh_at: Some(Utc::now()),
        auth_verification_material_last_refresh_error: None,
        registry_metadata: RegistryMetadataFeed::default(),
        registry_metadata_last_successful_refresh_at: Some(Utc::now()),
        registry_metadata_last_refresh_error: None,
        capacity_health: CapacityHealthFeed::default(),
        capacity_health_last_successful_refresh_at: Some(Utc::now()),
        capacity_health_last_refresh_error: None,
        peer_gateways: Vec::new(),
        relay_hmac_secret: None,
        managed_public_endpoint_negative_cache: Arc::new(std::sync::Mutex::new(HashMap::new())),
        stale_after_secs: CONNECTED_READ_MODEL_DEFAULT_STALE_AFTER_SECS,
    }
}

fn negative_cache_entry_count(read_model: &ConnectedGatewayReadModelSnapshot) -> usize {
    #[allow(clippy::expect_used)]
    read_model
        .managed_public_endpoint_negative_cache
        .lock()
        .expect("managed public endpoint negative cache lock")
        .len()
}

fn rebuild_read_model_indexes(read_model: &mut ConnectedGatewayReadModelSnapshot) {
    read_model.publication_catalog_shards =
        build_managed_public_endpoint_catalog_shards(&read_model.publication_catalog);
    read_model.routing_compatibility_index =
        build_routing_compatibility_index(&read_model.routing_compatibility);
}

#[test]
fn rejects_unpublished_ingress_hostname() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );

    let response = enforce_managed_public_endpoint_publication_binding(
        &fresh_read_model(vec![publication(
            "abc123def456.ai.us.verdictan.com",
            "published",
        )]),
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn accepts_published_ingress_hostname_case_insensitively() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("ABC123DEF456.AI.EU.VERDICTAN.COM:443"),
    );

    let response = enforce_managed_public_endpoint_publication_binding(
        &fresh_read_model(vec![publication(
            "abc123def456.ai.eu.verdictan.com",
            "published",
        )]),
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    );

    assert!(response.is_none());
}

#[test]
fn ignores_direct_gateway_requests_without_ingress_marker() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:41002"));

    let response = enforce_managed_public_endpoint_publication_binding(
        &fresh_read_model(Vec::new()),
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    );

    assert!(response.is_none());
}

#[test]
fn locality_scope_fragment_includes_region_group_and_host() {
    assert_eq!(
        locality_scope_fragment(Some("eu"), Some("abc123def456.ai.eu.verdictan.com")),
        Some("region_group:eu:host:abc123def456.ai.eu.verdictan.com".to_string())
    );
    assert_eq!(
        locality_scope_fragment(Some("global"), None),
        Some("region_group:global".to_string())
    );
    assert_eq!(
        locality_scope_fragment(None, Some("abc123def456.ai.global.verdictan.com")),
        Some("host:abc123def456.ai.global.verdictan.com".to_string())
    );
    assert_eq!(locality_scope_fragment(None, None), None);
}

#[test]
fn rejects_regional_hostname_when_publication_region_group_differs() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );
    headers.insert(
        "x-verdictan-requested-region-group",
        HeaderValue::from_static("eu"),
    );

    let mut publication = publication("abc123def456.ai.eu.verdictan.com", "published");
    publication.primary_region_group_key = Some("us".to_string());

    let response = enforce_managed_public_endpoint_publication_binding(
        &fresh_read_model(vec![publication]),
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn rejects_public_ingress_when_gateway_region_metadata_is_missing() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );

    let mut publication = publication("abc123def456.ai.eu.verdictan.com", "published");
    publication.primary_region_group_key = Some("eu-sovereign".to_string());

    let mut read_model = fresh_read_model(vec![publication]);
    read_model.region_key = None;

    let response = enforce_managed_public_endpoint_publication_binding(
        &read_model,
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn rejects_public_ingress_without_active_revision_metadata() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );

    let response = enforce_managed_public_endpoint_publication_binding(
        &fresh_read_model(vec![
            crate::runtime::ConnectedGatewayPublicationDescriptor {
                family_key: "global".to_string(),
                publication_key: "pub_123".to_string(),
                published_hostname: Some("abc123def456.ai.eu.verdictan.com".to_string()),
                publication_state: "published".to_string(),
                active_revision_id: None,
                active_revision_readiness_state: None,
                active_revision_auth_digest: None,
                active_revision_policy_digest: None,
                active_revision_pool_membership_issue: None,
                locality_mode: "region_pinned".to_string(),
                serving_fleet_class: "managed".to_string(),
                primary_region_group_key: None,
            },
        ]),
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn rejects_public_ingress_without_active_revision_auth_digest() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );

    let response = enforce_managed_public_endpoint_publication_binding(
        &fresh_read_model(vec![
            crate::runtime::ConnectedGatewayPublicationDescriptor {
                family_key: "global".to_string(),
                publication_key: "pub_123".to_string(),
                published_hostname: Some("abc123def456.ai.eu.verdictan.com".to_string()),
                publication_state: "published".to_string(),
                active_revision_id: Some("rev-active".to_string()),
                active_revision_readiness_state: Some("active".to_string()),
                active_revision_auth_digest: None,
                active_revision_policy_digest: Some("policy-digest-active".to_string()),
                active_revision_pool_membership_issue: None,
                locality_mode: "region_pinned".to_string(),
                serving_fleet_class: "managed".to_string(),
                primary_region_group_key: None,
            },
        ]),
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn rejects_public_ingress_without_active_revision_policy_digest() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );

    let response = enforce_managed_public_endpoint_publication_binding(
        &fresh_read_model(vec![
            crate::runtime::ConnectedGatewayPublicationDescriptor {
                family_key: "global".to_string(),
                publication_key: "pub_123".to_string(),
                published_hostname: Some("abc123def456.ai.eu.verdictan.com".to_string()),
                publication_state: "published".to_string(),
                active_revision_id: Some("rev-active".to_string()),
                active_revision_readiness_state: Some("active".to_string()),
                active_revision_auth_digest: Some("auth-digest-active".to_string()),
                active_revision_policy_digest: None,
                active_revision_pool_membership_issue: None,
                locality_mode: "region_pinned".to_string(),
                serving_fleet_class: "managed".to_string(),
                primary_region_group_key: None,
            },
        ]),
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn rejects_public_ingress_when_active_revision_is_not_ready() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );

    let response = enforce_managed_public_endpoint_publication_binding(
        &fresh_read_model(vec![
            crate::runtime::ConnectedGatewayPublicationDescriptor {
                family_key: "global".to_string(),
                publication_key: "pub_123".to_string(),
                published_hostname: Some("abc123def456.ai.eu.verdictan.com".to_string()),
                publication_state: "published".to_string(),
                active_revision_id: Some("rev-active".to_string()),
                active_revision_readiness_state: Some("materializing".to_string()),
                active_revision_auth_digest: Some("auth-digest-active".to_string()),
                active_revision_policy_digest: Some("policy-digest-active".to_string()),
                active_revision_pool_membership_issue: None,
                locality_mode: "region_pinned".to_string(),
                serving_fleet_class: "managed".to_string(),
                primary_region_group_key: None,
            },
        ]),
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn rejects_public_ingress_when_connected_cell_pool_publication_does_not_admit_current_gateway() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );

    let response = enforce_managed_public_endpoint_publication_binding(
        &fresh_read_model(vec![
            crate::runtime::ConnectedGatewayPublicationDescriptor {
                family_key: "global".to_string(),
                publication_key: "pub_123".to_string(),
                published_hostname: Some("abc123def456.ai.eu.verdictan.com".to_string()),
                publication_state: "published".to_string(),
                active_revision_id: Some("rev-active".to_string()),
                active_revision_readiness_state: Some("active".to_string()),
                active_revision_auth_digest: Some("auth-digest-active".to_string()),
                active_revision_policy_digest: Some("policy-digest-active".to_string()),
                active_revision_pool_membership_issue: Some(
                    "current_gateway_not_admitted".to_string(),
                ),
                locality_mode: "region_pinned".to_string(),
                serving_fleet_class: "connected_cell_pool".to_string(),
                primary_region_group_key: None,
            },
        ]),
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn rejects_stale_read_model_for_managed_public_endpoint_requests() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );

    let mut read_model = fresh_read_model(vec![publication(
        "abc123def456.ai.eu.verdictan.com",
        "published",
    )]);
    read_model.publication_catalog_last_successful_refresh_at =
        Some(Utc::now() - Duration::seconds(CONNECTED_READ_MODEL_DEFAULT_STALE_AFTER_SECS + 1));
    read_model.publication_catalog_last_refresh_error =
        Some("control plane unavailable".to_string());

    let response = enforce_managed_public_endpoint_publication_binding(
        &read_model,
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn rejects_known_host_when_routing_compatibility_feed_is_stale() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );

    let mut read_model = fresh_read_model(vec![publication(
        "abc123def456.ai.eu.verdictan.com",
        "published",
    )]);
    read_model.routing_compatibility_last_successful_refresh_at =
        Some(Utc::now() - Duration::seconds(CONNECTED_READ_MODEL_DEFAULT_STALE_AFTER_SECS + 1));
    read_model.routing_compatibility_last_refresh_error =
        Some("routing compatibility refresh failed".to_string());

    let response = enforce_managed_public_endpoint_publication_binding(
        &read_model,
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn rejects_known_host_when_routing_compatibility_revision_does_not_match_active_revision() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.eu.verdictan.com"),
    );

    let mut read_model = fresh_read_model(vec![publication(
        "abc123def456.ai.eu.verdictan.com",
        "published",
    )]);
    read_model.routing_compatibility[0].active_revision_id = Some("rev-other".to_string());
    rebuild_read_model_indexes(&mut read_model);

    let response = enforce_managed_public_endpoint_publication_binding(
        &read_model,
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn caches_unknown_managed_public_endpoint_misses() {
    let read_model = fresh_read_model(vec![publication(
        "abc123def456.ai.eu.verdictan.com",
        "published",
    )]);

    assert_eq!(negative_cache_entry_count(&read_model), 0);
    assert!(candidate_managed_public_endpoint_publication(
        &read_model,
        "unknown00000000.ai.eu.verdictan.com",
    )
    .is_none());
    assert_eq!(negative_cache_entry_count(&read_model), 1);
    assert!(candidate_managed_public_endpoint_publication(
        &read_model,
        "unknown00000000.ai.eu.verdictan.com",
    )
    .is_none());
    assert_eq!(negative_cache_entry_count(&read_model), 1);
}

#[test]
fn refresh_success_clears_unknown_host_negative_cache() {
    let seed = fresh_read_model(vec![publication(
        "abc123def456.ai.eu.verdictan.com",
        "published",
    )]);
    let shared = SharedConnectedGatewayReadModel::new(
        seed.region_key.clone(),
        seed.publication_catalog.clone(),
        seed.publication_catalog_last_successful_refresh_at,
        seed.routing_compatibility.clone(),
        seed.routing_compatibility_last_successful_refresh_at,
    );
    let snapshot = shared.snapshot();
    assert!(candidate_managed_public_endpoint_publication(
        &snapshot,
        "unknown00000000.ai.eu.verdictan.com",
    )
    .is_none());
    assert_eq!(negative_cache_entry_count(&snapshot), 1);

    shared.record_success(
        snapshot.region_key.clone(),
        snapshot.publication_catalog.clone(),
        snapshot.routing_compatibility.clone(),
        Vec::new(),
        None,
        Utc::now(),
    );

    let refreshed = shared.snapshot();
    assert_eq!(negative_cache_entry_count(&refreshed), 0);
}

#[test]
fn rejects_unknown_host_without_needing_fresh_routing_compatibility() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_static("abc123def456.ai.us.verdictan.com"),
    );

    let mut read_model = fresh_read_model(vec![publication(
        "abc123def456.ai.eu.verdictan.com",
        "published",
    )]);
    read_model.routing_compatibility = Vec::new();
    read_model.routing_compatibility_last_successful_refresh_at =
        Some(Utc::now() - Duration::seconds(CONNECTED_READ_MODEL_DEFAULT_STALE_AFTER_SECS + 1));
    read_model.routing_compatibility_last_refresh_error =
        Some("routing compatibility refresh failed".to_string());

    let response = enforce_managed_public_endpoint_publication_binding(
        &read_model,
        &headers,
        "req_123",
        "00-11111111111111111111111111111111-1111111111111111-01",
    )
    .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn health_check_flags_publications_missing_policy_digest() {
    let publication = crate::runtime::ConnectedGatewayPublicationDescriptor {
        family_key: "global".to_string(),
        publication_key: "pub_123".to_string(),
        published_hostname: Some("abc123def456.ai.eu.verdictan.com".to_string()),
        publication_state: "published".to_string(),
        active_revision_id: Some("rev-active".to_string()),
        active_revision_readiness_state: Some("active".to_string()),
        active_revision_auth_digest: Some("auth-digest-active".to_string()),
        active_revision_policy_digest: None,
        active_revision_pool_membership_issue: None,
        locality_mode: "region_pinned".to_string(),
        serving_fleet_class: "managed".to_string(),
        primary_region_group_key: Some("eu".to_string()),
    };
    let read_model = fresh_read_model(vec![publication]);
    let issue = first_managed_public_endpoint_health_issue(&read_model);

    assert_eq!(
        issue.map(|(publication, reason)| (publication.publication_key, reason)),
        Some((
            "pub_123".to_string(),
            "active_revision_policy_digest_missing".to_string()
        ))
    );
}

#[test]
fn health_check_flags_publications_missing_matching_routing_compatibility_revision() {
    let publication = publication("abc123def456.ai.eu.verdictan.com", "published");
    let mut read_model = fresh_read_model(vec![publication]);
    read_model.routing_compatibility[0].active_revision_id = Some("rev-other".to_string());
    rebuild_read_model_indexes(&mut read_model);
    let issue = first_managed_public_endpoint_health_issue(&read_model);

    assert_eq!(
        issue.map(|(publication, reason)| (publication.publication_key, reason)),
        Some((
            "pub_123".to_string(),
            "active_revision_readiness_state_missing".to_string()
        ))
    );
}

#[test]
fn health_check_flags_connected_cell_pool_publications_without_admitted_member_eligibility() {
    let publication = crate::runtime::ConnectedGatewayPublicationDescriptor {
        family_key: "global".to_string(),
        publication_key: "pub_123".to_string(),
        published_hostname: Some("abc123def456.ai.eu.verdictan.com".to_string()),
        publication_state: "published".to_string(),
        active_revision_id: Some("rev-active".to_string()),
        active_revision_readiness_state: Some("active".to_string()),
        active_revision_auth_digest: Some("auth-digest-active".to_string()),
        active_revision_policy_digest: Some("policy-digest-active".to_string()),
        active_revision_pool_membership_issue: Some("current_gateway_not_admitted".to_string()),
        locality_mode: "region_pinned".to_string(),
        serving_fleet_class: "connected_cell_pool".to_string(),
        primary_region_group_key: Some("eu".to_string()),
    };
    let read_model = fresh_read_model(vec![publication]);
    let issue = first_managed_public_endpoint_health_issue(&read_model);

    assert_eq!(
        issue.map(|(publication, reason)| (publication.publication_key, reason)),
        Some((
            "pub_123".to_string(),
            "current_gateway_not_admitted".to_string(),
        ))
    );
}

#[test]
fn connected_cell_pool_admission_matches_nested_member_identity_when_healthy() {
    let admitted_members = serde_json::json!({
        "members": [{
            "runtime_registration_id": "runtime-eu-1",
            "healthy": true,
            "status": "active"
        }]
    });

    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &admitted_members,
            Some("runtime-eu-1"),
            Some("gateway-eu-1"),
        ),
        ConnectedCellPoolAdmissionMatch::Matched
    );
}

#[test]
fn connected_cell_pool_admission_rejects_unhealthy_identity_member() {
    let admitted_members = serde_json::json!({
        "members": [{
            "gateway_id": "gateway-eu-1",
            "healthy": false,
            "status": "active"
        }]
    });

    assert_eq!(
        evaluate_connected_cell_pool_admitted_members(
            &admitted_members,
            Some("runtime-eu-1"),
            Some("gateway-eu-1"),
        ),
        ConnectedCellPoolAdmissionMatch::NotMatched
    );
}

#[test]
fn pool_membership_issue_requires_runtime_or_gateway_identity() {
    assert_eq!(
        active_revision_pool_membership_issue_for_gateway(
            "connected_cell_pool",
            None,
            None,
            Some(&serde_json::json!(["runtime-eu-1"])),
        ),
        Some("runtime_pool_identity_missing")
    );
}

#[test]
fn pool_membership_issue_rejects_unrecognized_admitted_member_payload() {
    assert_eq!(
        active_revision_pool_membership_issue_for_gateway(
            "connected_cell_pool",
            Some("runtime-eu-1"),
            Some("gateway-eu-1"),
            Some(&serde_json::json!({"members": [{"status": "active"}]})),
        ),
        Some("active_revision_admitted_members_unrecognized")
    );
}

#[test]
fn publication_region_vrn_resource_fails_closed_on_region_mismatch() {
    let mut publication = publication("abc123def456.ai.eu.verdictan.com", "published");
    publication.primary_region_group_key = Some("eu".to_string());

    assert_eq!(
        publication_region_vrn_resource(&publication, Some("us")),
        None
    );
    assert_eq!(
        publication_region_vrn_resource(&publication, Some("eu")),
        Some("publication/pub_123".to_string())
    );
}

#[test]
fn publication_binding_issue_requires_hostname_only_for_public_states() {
    let mut published = publication("abc123def456.ai.eu.verdictan.com", "published");
    published.published_hostname = None;
    assert_eq!(
        publication_public_binding_issue(&published),
        Some("published_hostname_missing".to_string())
    );

    let mut draft = published.clone();
    draft.publication_state = "draft".to_string();
    assert_eq!(publication_public_binding_issue(&draft), None);
}

fn configured_ingress_tls() -> crate::gateway::relay::RelayTlsConfig {
    crate::gateway::relay::RelayTlsConfig {
        cert_pem: Some(b"cert".to_vec()),
        key_pem: Some(b"key".to_vec()),
        ca_cert_pem: Some(b"ca".to_vec()),
    }
}

fn managed_public_spoof_headers(hostname: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-verdictan-public-endpoint",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-public-hostname",
        HeaderValue::from_str(hostname).expect("hostname header"),
    );
    headers.insert(
        "host",
        HeaderValue::from_str(hostname).expect("host header"),
    );
    headers
}

fn relay_authenticated_managed_public_headers(hostname: &str) -> HeaderMap {
    let mut headers = managed_public_spoof_headers(hostname);
    headers.insert(
        "x-verdictan-relay-client-cert-verified",
        HeaderValue::from_static("true"),
    );
    headers.insert(
        "x-verdictan-relay-token",
        HeaderValue::from_static("relay-secret"),
    );
    headers
}

#[test]
fn managed_public_direct_header_spoof_is_stripped() {
    let mut headers = managed_public_spoof_headers("managed-public.ai.eu.verdictan.com");
    let peer: std::net::IpAddr = "203.0.113.10".parse().unwrap();
    let admission = admit_or_strip_managed_public_ingress(
        &mut headers,
        peer,
        &[],
        &crate::gateway::relay::RelayTlsConfig::default(),
        None,
        "req-spoof",
        "00-trace",
    )
    .expect("direct spoof must not hard-fail");

    assert_eq!(admission, ManagedPublicIngressAdmission::Absent);
    assert!(
        !has_managed_public_ingress_headers(&headers),
        "direct spoof headers must be stripped"
    );
    assert!(!ingress_marks_managed_public_endpoint(&headers));
}

#[test]
fn managed_public_trusted_ingress_succeeds() {
    let hostname = "managed-public.ai.eu.verdictan.com";
    let headers = relay_authenticated_managed_public_headers(hostname);
    let cidrs = crate::gateway::network::parse_trusted_proxy_cidrs(&["10.0.0.0/8".to_string()])
        .expect("cidrs");
    let peer: std::net::IpAddr = "10.1.2.3".parse().unwrap();

    let admission = admit_managed_public_ingress(
        &headers,
        peer,
        &cidrs,
        &configured_ingress_tls(),
        Some("relay-secret"),
        "req-trusted",
        "00-trace",
    )
    .expect("trusted ingress must admit");

    assert_eq!(admission, ManagedPublicIngressAdmission::Admitted);
    assert!(ingress_marks_managed_public_endpoint(&headers));
}

#[test]
fn managed_public_mtls_mismatch_fails() {
    let hostname = "managed-public.ai.eu.verdictan.com";
    let mut headers = managed_public_spoof_headers(hostname);
    headers.insert(
        "x-verdictan-relay-token",
        HeaderValue::from_static("relay-secret"),
    );
    let cidrs = crate::gateway::network::parse_trusted_proxy_cidrs(&["10.0.0.0/8".to_string()])
        .expect("cidrs");
    let peer: std::net::IpAddr = "10.1.2.3".parse().unwrap();

    let err = admit_managed_public_ingress(
        &headers,
        peer,
        &cidrs,
        &configured_ingress_tls(),
        Some("relay-secret"),
        "req-mtls",
        "00-trace",
    )
    .expect_err("CIDR without verified mTLS must fail");
    assert_eq!(err.status(), StatusCode::FORBIDDEN);
}

#[test]
fn managed_public_transport_token_mismatch_fails() {
    let hostname = "managed-public.ai.eu.verdictan.com";
    let headers = relay_authenticated_managed_public_headers(hostname);
    let cidrs = crate::gateway::network::parse_trusted_proxy_cidrs(&["10.0.0.0/8".to_string()])
        .expect("cidrs");
    let peer: std::net::IpAddr = "10.1.2.3".parse().unwrap();

    let err = admit_managed_public_ingress(
        &headers,
        peer,
        &cidrs,
        &configured_ingress_tls(),
        Some("wrong-secret"),
        "req-transport",
        "00-trace",
    )
    .expect_err("verified mTLS without the shared relay token must fail");
    assert_eq!(err.status(), StatusCode::FORBIDDEN);
}

#[test]
fn managed_public_cidr_mismatch_fails() {
    let hostname = "managed-public.ai.eu.verdictan.com";
    let headers = relay_authenticated_managed_public_headers(hostname);
    let cidrs = crate::gateway::network::parse_trusted_proxy_cidrs(&["10.0.0.0/8".to_string()])
        .expect("cidrs");
    let peer: std::net::IpAddr = "203.0.113.10".parse().unwrap();

    let err = admit_managed_public_ingress(
        &headers,
        peer,
        &cidrs,
        &configured_ingress_tls(),
        Some("relay-secret"),
        "req-cidr",
        "00-trace",
    )
    .expect_err("mTLS without trusted CIDR must fail");
    assert_eq!(err.status(), StatusCode::FORBIDDEN);
}

#[test]
fn managed_public_hostname_mismatch_fails() {
    let mut headers =
        relay_authenticated_managed_public_headers("managed-public.ai.eu.verdictan.com");
    headers.insert(
        "host",
        HeaderValue::from_static("other.ai.eu.verdictan.com"),
    );
    let cidrs = crate::gateway::network::parse_trusted_proxy_cidrs(&["10.0.0.0/8".to_string()])
        .expect("cidrs");
    let peer: std::net::IpAddr = "10.1.2.3".parse().unwrap();

    let err = admit_managed_public_ingress(
        &headers,
        peer,
        &cidrs,
        &configured_ingress_tls(),
        Some("relay-secret"),
        "req-host",
        "00-trace",
    )
    .expect_err("hostname mismatch must fail");
    assert_eq!(err.status(), StatusCode::FORBIDDEN);
    assert!(!managed_public_hostname_matches_host(&headers));
}
