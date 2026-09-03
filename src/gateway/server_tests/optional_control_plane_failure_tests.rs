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

#[test]
fn known_permission_and_missing_route_errors_fail_open() {
    assert!(is_optional_control_plane_capability_failure(
        StatusCode::FORBIDDEN,
        r#"{"error":{"code":"auth.insufficient_permissions"}}"#,
    ));
    assert!(is_optional_control_plane_capability_failure(
        StatusCode::FORBIDDEN,
        r#"{"error":{"code":"auth.admin_surface_required"}}"#,
    ));
    assert!(is_optional_control_plane_capability_failure(
        StatusCode::NOT_FOUND,
        r#"{"error":{"code":"not_found"}}"#,
    ));
    assert!(!is_optional_control_plane_capability_failure(
        StatusCode::FORBIDDEN,
        r#"{"error":{"code":"gateway_machine.invalid_service_scope"}}"#,
    ));
    assert!(!is_optional_control_plane_capability_failure(
        StatusCode::UNPROCESSABLE_ENTITY,
        r#"{"error":{"code":"validation.failed"}}"#,
    ));
}
