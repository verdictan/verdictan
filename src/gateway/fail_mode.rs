// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    Allow,
    Block,
}

impl FailMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

impl serde::Serialize for FailMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            FailMode::Allow => "allow",
            FailMode::Block => "block",
        })
    }
}

impl<'de> serde::Deserialize<'de> for FailMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        FailMode::parse(&s)
            .ok_or_else(|| serde::de::Error::unknown_variant(&s, &["allow", "block"]))
    }
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
    fn fail_mode_parse_allow() {
        assert_eq!(FailMode::parse("allow"), Some(FailMode::Allow));
    }

    #[test]
    fn fail_mode_parse_block() {
        assert_eq!(FailMode::parse("block"), Some(FailMode::Block));
    }

    #[test]
    fn fail_mode_parse_unknown_returns_none() {
        assert_eq!(FailMode::parse("invalid"), None);
        assert_eq!(FailMode::parse(""), None);
        assert_eq!(FailMode::parse("ALLOW"), None);
    }

    #[test]
    fn fail_mode_serde_roundtrip() {
        let allow_json = serde_json::to_string(&FailMode::Allow).unwrap();
        assert_eq!(allow_json, "\"allow\"");
        let block_json = serde_json::to_string(&FailMode::Block).unwrap();
        assert_eq!(block_json, "\"block\"");

        let deserialized: FailMode = serde_json::from_str("\"allow\"").unwrap();
        assert_eq!(deserialized, FailMode::Allow);
        let deserialized: FailMode = serde_json::from_str("\"block\"").unwrap();
        assert_eq!(deserialized, FailMode::Block);
    }

    #[test]
    fn fail_mode_serde_invalid_variant_errors() {
        let result: Result<FailMode, _> = serde_json::from_str("\"invalid\"");
        assert!(result.is_err());
    }
}
