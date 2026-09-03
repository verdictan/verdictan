// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use crate::error::CliError;

fn parse_schema_json(text: &str) -> Result<serde_json::Value, CliError> {
    serde_json::from_str(text).map_err(|e| {
        CliError::internal(format!("failed to parse embedded policy schema JSON: {e}"))
    })
}

pub(crate) fn load_schema_json() -> Result<serde_json::Value, CliError> {
    let text = include_str!("../../schema/policy-configuration.schema.json");
    parse_schema_json(text)
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
    fn command_helper_coverage_load_schema_json_parses_embedded_document() {
        let schema = load_schema_json().expect("embedded schema should parse");
        assert!(schema.is_object());
        assert!(schema.get("$schema").is_some() || schema.get("type").is_some());
    }

    #[test]
    fn parse_schema_json_maps_invalid_json_to_internal_error() {
        let error = parse_schema_json("{invalid json").expect_err("invalid schema should fail");
        let message = error.to_string();

        assert!(message.contains("failed to parse embedded policy schema JSON"));
        assert!(message.contains("line"));
    }
}
