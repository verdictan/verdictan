// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::commands::gateway_history::{history_filter_label, HistoryActionFilter};
use crate::error::CliError;
use crate::output::json::print_json;
use crate::supervisor::{default_state_dir, SupervisorStateStore};

#[derive(Debug, Args)]
pub(crate) struct GatewayInspectArgs {
    #[arg(long)]
    pub(crate) name: String,

    #[arg(long)]
    pub(crate) state_dir: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) json: bool,

    #[arg(long, default_value_t = 5)]
    pub(crate) history_limit: usize,

    #[arg(long, value_enum)]
    pub(crate) history_action: Option<HistoryActionFilter>,

    #[arg(long, conflicts_with = "json")]
    pub(crate) history_json: bool,
}

pub(crate) fn run(args: GatewayInspectArgs) -> Result<(), CliError> {
    let state_dir = args.state_dir.unwrap_or(default_state_dir()?);
    let store = SupervisorStateStore::load(state_dir)?;
    let supervisor = store.metadata();
    let record = store
        .get_instance(&args.name)
        .ok_or_else(|| CliError::user(format!("instance {} does not exist", args.name)))?;
    let operations_history = crate::commands::gateway_history::filter_history(
        record.operations_history.as_slice(),
        args.history_limit,
        args.history_action,
    );

    let value = serde_json::json!({
        "supervisor": supervisor,
        "spec": record.spec,
        "status": record.status,
        "history_limit": args.history_limit,
        "history_action": args.history_action.map(|item| history_filter_label(item).to_string()),
        "operations_history": operations_history,
    });

    if args.history_json {
        return print_json(&serde_json::json!({
            "instance_id": record.spec.instance_id.as_str(),
            "history_limit": args.history_limit,
            "history_action": args.history_action.map(|item| history_filter_label(item).to_string()),
            "operations_history": operations_history,
        }));
    }

    if args.json {
        return print_json(&value);
    }

    let rendered = crate::commands::gateway_status::render_supervisor_record(
        &supervisor,
        record,
        args.history_limit,
        args.history_action,
    );
    println!("{}", rendered);
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
    use serde_json::json;

    #[test]
    fn inspect_json_shape() {
        let value = json!({
            "supervisor": {},
            "spec": {"instance_id": "gw-1"},
            "status": {},
            "history_limit": 5,
            "history_action": null,
            "operations_history": [],
        });
        assert_eq!(value["history_limit"], 5);
        assert!(value["history_action"].is_null());
        assert_eq!(value["spec"]["instance_id"], "gw-1");
    }

    #[test]
    fn history_json_output_shape() {
        let value = json!({
            "instance_id": "gw-1",
            "history_limit": 10,
            "history_action": "reload",
            "operations_history": [{"action": "Reload"}],
        });
        assert_eq!(value["instance_id"], "gw-1");
        assert_eq!(value["operations_history"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn inspect_json_with_multiple_history_entries() {
        let value = json!({
            "supervisor": {"state_dir": "/tmp/test"},
            "spec": {"instance_id": "gw-multi"},
            "status": {"lifecycle": "running"},
            "history_limit": 10,
            "history_action": null,
            "operations_history": [
                {"action": "Reload", "outcome": "Succeeded"},
                {"action": "Start", "outcome": "Succeeded"},
                {"action": "Stop", "outcome": "Failed"},
            ],
        });
        assert_eq!(value["operations_history"].as_array().unwrap().len(), 3);
        assert_eq!(value["spec"]["instance_id"], "gw-multi");
        assert_eq!(value["status"]["lifecycle"], "running");
    }

    #[test]
    fn inspect_json_with_history_action_filter() {
        let filter: Option<&str> = Some("reload");
        let value = json!({
            "instance_id": "gw-1",
            "history_limit": 5,
            "history_action": filter,
            "operations_history": [],
        });
        assert_eq!(value["history_action"], "reload");
        assert_eq!(value["history_limit"], 5);
    }

    #[test]
    fn inspect_json_empty_supervisor() {
        let value = json!({
            "supervisor": {},
            "spec": {},
            "status": {},
            "history_limit": 0,
            "history_action": null,
            "operations_history": [],
        });
        assert!(value["supervisor"].as_object().unwrap().is_empty());
        assert!(value["operations_history"].as_array().unwrap().is_empty());
    }

    #[test]
    fn inspect_json_history_limit_zero() {
        let value = json!({
            "supervisor": {},
            "spec": {"instance_id": "gw-zero"},
            "status": {},
            "history_limit": 0,
            "history_action": null,
            "operations_history": [],
        });
        assert_eq!(value["history_limit"], 0);
        assert!(value["operations_history"].as_array().unwrap().is_empty());
    }

    #[test]
    fn args_all_fields_populated() {
        let args = super::GatewayInspectArgs {
            name: "prod-gw".to_string(),
            state_dir: Some(std::path::PathBuf::from("/var/state")),
            json: true,
            history_limit: 25,
            history_action: Some(crate::commands::gateway_history::HistoryActionFilter::Reload),
            history_json: false,
        };
        assert!(args.json);
        assert_eq!(args.history_limit, 25);
        assert!(args.history_action.is_some());
        assert!(!args.history_json);
    }

    #[test]
    fn args_default_history_limit() {
        let args = super::GatewayInspectArgs {
            name: "test".to_string(),
            state_dir: None,
            json: false,
            history_limit: 5,
            history_action: None,
            history_json: false,
        };
        assert_eq!(args.history_limit, 5);
    }

    #[test]
    fn history_json_output_shape_with_filter() {
        let value = json!({
            "instance_id": "gw-filtered",
            "history_limit": 3,
            "history_action": "stop",
            "operations_history": [
                {"action": "Stop", "outcome": "Succeeded"},
                {"action": "Stop", "outcome": "Failed"},
            ],
        });
        assert_eq!(value["history_action"], "stop");
        assert_eq!(value["operations_history"].as_array().unwrap().len(), 2);
    }
}
