// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

pub const VALID_ACTIONS: &[&str] = &[
    "spend:read",
    "spend:write",
    "budgets:read",
    "budgets:write",
    "budgets:create",
    "budgets:update",
    "budgets:delete",
    "events:read",
    "events:write",
    "events:export",
    "escalations:read",
    "escalations:claim",
    "escalations:resolve",
    "configs:read",
    "configs:write",
    "config_vars:resolve",
    "gateways:read",
    "gateways:write",
    "gateways:deploy",
    "gateways:admin",
    "gateways:register",
    "gateways:rotate_token",
    "gateways:bind_agent",
    "gateways:unbind_agent",
    "gateways:update_policy",
    "gateways:report_status",
    "templates:read",
    "templates:write",
    "exports:read",
    "exports:write",
    "exports:download",
    "exports:admin",
    "notifications:read",
    "notifications:manage",
    "history:read",
    "history:write",
    "history:learn",
    "agent_call_traces:read",
    "agent_call_traces:write",
    "agent_tool_call_traces:read",
    "agent_tool_call_traces:write",
    "work_receipts:read",
    "work_receipts:write",
    "projects:list",
    "projects:create",
    "projects:read",
    "projects:update",
    "projects:archive",
    "projects:assign",
    "projects:tags:read",
    "projects:tags:write",
    "secrets:list",
    "secrets:read",
    "secrets:write",
    "users:read",
    "users:invite",
    "users:manage",
    "teams:read",
    "teams:manage",
    "roles:read",
    "roles:write",
    "roles:assign",
    "policies:read",
    "policies:write",
    "org:settings",
    "org:sso",
    "org:audit",
    "org:trail:read",
    "org:trail:admin",
    "organizations:read",
    "organizations:write",
    "organizations:manage",
    "signup_requests:read",
    "signup_requests:review",
    "archive_requests:read",
    "archive_requests:review",
    "platform:admin",
    "platform_admins:read",
    "platform_admins:write",
    "agents:read",
    "agents:write",
    "agents:admin",
    "agents:list",
    "agents:create",
    "agents:update",
    "agents:delete",
    "agents:deploy",
    "agents:bind_gateway",
    "agents:unbind_gateway",
    "agents:review",
    "models:read",
    "models:admin",
    "pricing:read",
    "model_pricing:read",
    "model_pricing:write",
    "gateway_execution:read",
    "gateway_execution:write",
    "keys:read",
    "context:read",
    "tokens:list",
    "tokens:create",
    "tokens:read",
    "tokens:update",
    "tokens:rotate",
    "tokens:revoke",
    "tokens:validate",
    "tokens:bind_runtime",
    "tokens:bind_budget",
    "tokens:use_gateway",
    "tokens:write",
    "governance:read",
    "governance:write",
    "activity:read",
    "activity:read_full",
    "activity:export",
    "tracing:read",
    "routing:read",
    "routing:admin",
    "cache:read",
    "configurations:read",
    "routes:admin",
    "routes:access",
    "surface:admin",
    "surface:management",
    "agents:manage_publication",
    "regions:read",
    "regions:write",
    "regions:admin",
    "tags:read",
    "tags:write",
    "tags:admin",
    "cache:write",
    "cache:invalidate",
    "cache:admin",
    "oauth_tokens:read",
    "oauth_tokens:write",
    "oauth_clients:read",
    "oauth_clients:write",
    "sso:read",
    "sso:write",
    "team_settings:read",
    "team_settings:write",
    "approvals:read",
    "approvals:write",
    "invitations:read",
    "invitations:write",
    "prompt_evals:read",
    "prompt_evals:write",
    "prompt_evals:admin",
];

const SUPPORTED_CONDITION_OPERATORS: &[&str] = &[
    "StringEquals",
    "string_equals",
    "StringLike",
    "string_like",
    "StringNotEquals",
    "string_not_equals",
    "Bool",
    "bool",
    "Null",
    "null",
    "NumericLessThanEquals",
    "numeric_less_than_equals",
    "NumericGreaterThanEquals",
    "numeric_greater_than_equals",
    "ForAnyValue:StringEquals",
    "for_any_value_string_equals",
    "mfa_required",
    "principal_tags",
    "resource_tags",
    "resource_names",
];

const KNOWN_STATEMENT_FIELDS: &[&str] = &[
    "sid",
    "Sid",
    "effect",
    "Effect",
    "actions",
    "Action",
    "resources",
    "Resource",
    "conditions",
    "Condition",
];

const KNOWN_DOCUMENT_FIELDS: &[&str] = &["Version", "Statement", "statements"];

pub fn validate_statement_document(value: &Value) -> Vec<String> {
    let raw_statements = match extract_raw_statements(value) {
        Ok(statements) => statements,
        Err(error) => return vec![error],
    };

    let mut messages = Vec::new();
    validate_no_unknown_fields(value, &raw_statements, &mut messages);

    if raw_statements.is_empty() {
        messages.push("At least one policy statement is required.".to_string());
        return messages;
    }

    for (index, statement) in raw_statements.iter().enumerate() {
        validate_statement(statement, index, &mut messages);
    }

    messages
}

fn extract_raw_statements(value: &Value) -> Result<Vec<Value>, String> {
    if let Some(array) = value.as_array() {
        return Ok(array.clone());
    }

    let Some(object) = value.as_object() else {
        return Err(
            "policy statements must be an array, a statement object, or a document with Statement/statements"
                .to_string(),
        );
    };

    if object.contains_key("effect") || object.contains_key("Effect") {
        return Ok(vec![value.clone()]);
    }

    if let Some(statements) = object.get("Statement").or_else(|| object.get("statements")) {
        return statements
            .as_array()
            .cloned()
            .ok_or_else(|| "policy document Statement field must be an array".to_string());
    }

    Err(
        "policy statements must be an array, a statement object, or a document with Statement/statements"
            .to_string(),
    )
}

fn validate_no_unknown_fields(value: &Value, raw_statements: &[Value], messages: &mut Vec<String>) {
    if let Some(object) = value.as_object() {
        let is_document = object.contains_key("Statement") || object.contains_key("statements");
        if is_document {
            for key in object.keys() {
                if !KNOWN_DOCUMENT_FIELDS.contains(&key.as_str()) {
                    messages.push(format!(
                        "Unknown document field `{key}`. Policy documents may only contain: Version, Statement"
                    ));
                }
            }
        }
    }

    for (index, statement) in raw_statements.iter().enumerate() {
        let Some(object) = statement.as_object() else {
            continue;
        };
        for key in object.keys() {
            if !KNOWN_STATEMENT_FIELDS.contains(&key.as_str()) {
                messages.push(format!(
                    "Unknown field `{key}` in statement {}. Identity policy statements may only contain: Sid, Effect, Action, Resource, Condition",
                    index + 1
                ));
            }
        }
        if let Some(conditions) = object
            .get("Condition")
            .or_else(|| object.get("conditions"))
            .and_then(Value::as_object)
        {
            for operator in conditions.keys() {
                if !SUPPORTED_CONDITION_OPERATORS.contains(&operator.as_str()) {
                    messages.push(format!(
                        "Unsupported condition operator `{operator}` in statement {}. Supported operators: StringEquals, StringLike, StringNotEquals, Bool, Null, NumericLessThanEquals, NumericGreaterThanEquals, ForAnyValue:StringEquals",
                        index + 1
                    ));
                }
            }
        }
    }
}

fn validate_statement(statement: &Value, index: usize, messages: &mut Vec<String>) {
    let Some(object) = statement.as_object() else {
        messages.push(format!("statement {} must be a JSON object", index + 1));
        return;
    };

    let effect = object
        .get("effect")
        .or_else(|| object.get("Effect"))
        .and_then(Value::as_str)
        .map(|value| value.to_ascii_lowercase());
    if !matches!(effect.as_deref(), Some("allow") | Some("deny")) {
        messages.push(format!(
            "statement {} must use effect allow or deny",
            index + 1
        ));
    }

    match extract_string_collection(object.get("actions").or_else(|| object.get("Action"))) {
        Some(actions) if !actions.is_empty() => {
            for action in actions {
                if !is_valid_action_pattern(action) {
                    messages.push(format!(
                        "statement {} uses unsupported action pattern `{action}`",
                        index + 1
                    ));
                }
            }
        }
        _ => messages.push(format!(
            "statement {} must include at least one action",
            index + 1
        )),
    }

    match extract_string_collection(object.get("resources").or_else(|| object.get("Resource"))) {
        Some(resources) if !resources.is_empty() => {
            for resource in resources {
                if let Err(error) = parse_resource_pattern(resource) {
                    messages.push(format!(
                        "statement {} has invalid resource pattern `{resource}`: {error}",
                        index + 1
                    ));
                }
            }
        }
        _ => messages.push(format!(
            "statement {} must include at least one resource",
            index + 1
        )),
    }

    if let Some(conditions) = object.get("conditions").or_else(|| object.get("Condition")) {
        validate_conditions(conditions, index, messages);
    }
}

fn validate_conditions(conditions: &Value, index: usize, messages: &mut Vec<String>) {
    let Some(object) = conditions.as_object() else {
        messages.push(format!(
            "statement {} conditions must be an object",
            index + 1
        ));
        return;
    };

    for (operator, operand) in object {
        match operator.as_str() {
            "mfa_required" => {
                if !operand.is_boolean() {
                    messages.push(format!(
                        "statement {} condition `mfa_required` must be a boolean",
                        index + 1
                    ));
                }
            }
            "principal_tags" | "resource_tags" => {
                validate_tag_condition_array(operator, operand, index, messages);
            }
            "resource_names" => {
                if !is_non_empty_string_array(operand) {
                    messages.push(format!(
                        "statement {} condition `{operator}` must be a non-empty string array",
                        index + 1
                    ));
                }
            }
            _ => validate_operator_object(operator, operand, index, messages),
        }
    }
}

fn validate_tag_condition_array(
    operator: &str,
    operand: &Value,
    index: usize,
    messages: &mut Vec<String>,
) {
    let Some(items) = operand.as_array() else {
        messages.push(format!(
            "statement {} condition `{operator}` must be an array of tag objects",
            index + 1
        ));
        return;
    };

    for (tag_index, item) in items.iter().enumerate() {
        let Some(object) = item.as_object() else {
            messages.push(format!(
                "statement {} condition `{operator}` tag {} must be an object",
                index + 1,
                tag_index + 1
            ));
            continue;
        };
        let key = object.get("key").and_then(Value::as_str).map(str::trim);
        let value = object.get("value").and_then(Value::as_str).map(str::trim);
        if key.is_none_or(str::is_empty) {
            messages.push(format!(
                "statement {} condition `{operator}` tag {} requires a non-empty key",
                index + 1,
                tag_index + 1
            ));
        }
        if value.is_none_or(str::is_empty) {
            messages.push(format!(
                "statement {} condition `{operator}` tag {} requires a non-empty value",
                index + 1,
                tag_index + 1
            ));
        }
    }
}

fn validate_operator_object(
    operator: &str,
    operand: &Value,
    index: usize,
    messages: &mut Vec<String>,
) {
    let Some(object) = operand.as_object() else {
        messages.push(format!(
            "statement {} condition operator `{operator}` must map to an object",
            index + 1
        ));
        return;
    };

    for (key, value) in object {
        if key.contains('.') && !key.starts_with("vt:") {
            messages.push(format!(
                "Dot-form condition key `{key}` in statement {} is not allowed. Use the canonical `vt:` namespace instead (for example, `vt:PrincipalTag/role` instead of `principal.tag.role`)",
                index + 1
            ));
        }

        let valid = match operator {
            "Bool" | "bool" | "Null" | "null" => value.is_boolean(),
            "NumericLessThanEquals"
            | "numeric_less_than_equals"
            | "NumericGreaterThanEquals"
            | "numeric_greater_than_equals" => value.is_number(),
            _ => is_string_or_string_array(value),
        };

        if !valid {
            messages.push(format!(
                "statement {} condition operator `{operator}` has an invalid value for `{key}`",
                index + 1
            ));
        }
    }
}

fn extract_string_collection(value: Option<&Value>) -> Option<Vec<&str>> {
    match value {
        Some(Value::String(value)) if !value.trim().is_empty() => Some(vec![value.as_str()]),
        Some(Value::Array(values)) => {
            let collected = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            Some(collected)
        }
        _ => None,
    }
}

fn is_non_empty_string_array(value: &Value) -> bool {
    value.as_array().is_some_and(|items| {
        !items.is_empty()
            && items
                .iter()
                .all(|item| item.as_str().is_some_and(|value| !value.trim().is_empty()))
    })
}

fn is_string_or_string_array(value: &Value) -> bool {
    match value {
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => {
            !values.is_empty()
                && values
                    .iter()
                    .all(|item| item.as_str().is_some_and(|value| !value.trim().is_empty()))
        }
        _ => false,
    }
}

fn is_valid_action_pattern(action: &str) -> bool {
    if action == "*" || VALID_ACTIONS.contains(&action) {
        return true;
    }
    action
        .strip_suffix(":*")
        .map(|namespace| {
            VALID_ACTIONS
                .iter()
                .any(|candidate| candidate.starts_with(&format!("{namespace}:")))
        })
        .unwrap_or(false)
}

fn parse_resource_pattern(resource: &str) -> Result<(), &'static str> {
    if resource == "*" || resource.starts_with("vdt:verdictan:") {
        return Ok(());
    }
    Err("resource must be '*' or a VDT pattern starting with 'vdt:verdictan:'")
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

    use super::validate_statement_document;
    use serde_json::json;

    #[test]
    fn validate_statement_document_accepts_document_with_statement_array() {
        let messages = validate_statement_document(&json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["events:*"],
                "Resource": ["vdt:verdictan:events/*"],
                "Condition": {
                    "StringEquals": {
                        "vt:PrincipalTag/role": "analyst"
                    }
                }
            }]
        }));
        assert!(messages.is_empty(), "{messages:?}");
    }

    #[test]
    fn validate_statement_document_rejects_statement_field_when_not_array() {
        let messages = validate_statement_document(&json!({
            "Statement": {
                "Effect": "Allow"
            }
        }));
        assert!(messages
            .iter()
            .any(|message| message.contains("Statement field must be an array")));
    }

    #[test]
    fn validate_statement_document_rejects_missing_action_and_resource() {
        let messages = validate_statement_document(&json!([{
            "Effect": "Allow"
        }]));
        assert!(messages
            .iter()
            .any(|message| message.contains("must include at least one action")));
        assert!(messages
            .iter()
            .any(|message| message.contains("must include at least one resource")));
    }

    #[test]
    fn validate_statement_document_rejects_invalid_resource_pattern() {
        let messages = validate_statement_document(&json!([{
            "Effect": "Allow",
            "Action": ["events:read"],
            "Resource": ["arn:aws:s3:::bucket"]
        }]));
        assert!(messages
            .iter()
            .any(|message| message.contains("invalid resource pattern")));
    }

    #[test]
    fn validate_statement_document_rejects_invalid_tag_condition_entries() {
        let messages = validate_statement_document(&json!([{
            "Effect": "Allow",
            "Action": ["events:read"],
            "Resource": ["*"],
            "Condition": {
                "principal_tags": [
                    {"key": "team"},
                    "oops"
                ]
            }
        }]));
        assert!(messages
            .iter()
            .any(|message| message.contains("requires a non-empty value")));
        assert!(messages
            .iter()
            .any(|message| message.contains("must be an object")));
    }

    #[test]
    fn validate_statement_document_rejects_non_object_condition_operands() {
        let messages = validate_statement_document(&json!([{
            "Effect": "Allow",
            "Action": ["events:read"],
            "Resource": ["*"],
            "Condition": {
                "StringEquals": "admin"
            }
        }]));
        assert!(messages
            .iter()
            .any(|message| message.contains("must map to an object")));
    }

    #[test]
    fn validate_statement_document_rejects_unsupported_action() {
        let messages = validate_statement_document(&json!([{
            "Effect": "Allow",
            "Action": ["unsupported:thing"],
            "Resource": ["*"],
            "Condition": {}
        }]));
        assert!(messages
            .iter()
            .any(|message| message.contains("unsupported action pattern")));
    }

    #[test]
    fn validate_statement_document_rejects_dot_form_condition_key() {
        let messages = validate_statement_document(&json!([{
            "Effect": "Allow",
            "Action": ["events:read"],
            "Resource": ["*"],
            "Condition": {
                "StringEquals": {
                    "principal.tag.role": "admin"
                }
            }
        }]));
        assert!(messages
            .iter()
            .any(|message| message.contains("Dot-form condition key")));
    }
}
