// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use crate::error::CliError;

pub(crate) fn print_json<T: serde::Serialize>(value: &T) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| CliError::internal(format!("failed to serialize JSON: {e}")))?;
    println!("{text}");
    Ok(())
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
    fn print_json_succeeds_for_serializable_value() {
        let data = serde_json::json!({"key": "value", "number": 42});
        let result = print_json(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn print_json_succeeds_for_primitive() {
        assert!(print_json(&"hello").is_ok());
        assert!(print_json(&42).is_ok());
        assert!(print_json(&true).is_ok());
    }

    #[test]
    fn print_json_succeeds_for_vec() {
        let data = vec!["a", "b", "c"];
        assert!(print_json(&data).is_ok());
    }

    #[test]
    fn print_json_succeeds_for_empty_object() {
        let data = serde_json::json!({});
        assert!(print_json(&data).is_ok());
    }
}
