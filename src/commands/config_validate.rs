// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::error::CliError;
use crate::gateway::declarative_config::{validate_config, LoadedDeclarativeConfig};
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct ConfigValidateArgs {
    /// Path to the YAML config file to validate.
    #[arg(long, default_value = "policy-config.yaml")]
    pub(crate) file: std::path::PathBuf,

    /// Print machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,
}

pub(crate) fn run(args: ConfigValidateArgs) -> Result<(), CliError> {
    let cfg = LoadedDeclarativeConfig::from_path_for_validation(&args.file)?;
    let errors = validate_config(&cfg);

    if args.json {
        return print_json(&validation_result_json(&args.file, &cfg, &errors));
    }

    print!("{}", render_validation_header(&args.file, &cfg));

    if errors.is_empty() {
        print!("{}", render_validation_success());
        Ok(())
    } else {
        for error in &errors {
            eprintln!("  ERROR: {error}");
        }
        Err(validation_error(&errors))
    }
}

fn validation_result_json(
    file: &std::path::Path,
    cfg: &LoadedDeclarativeConfig,
    errors: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "file": file.display().to_string(),
        "valid": errors.is_empty(),
        "config_version": cfg.config_version,
        "schema_version": cfg.schema_version,
        "errors": errors,
    })
}

fn render_validation_header(file: &std::path::Path, cfg: &LoadedDeclarativeConfig) -> String {
    format!(
        "Validating: {}\nConfig version: {}\n",
        file.display(),
        cfg.config_version
    )
}

fn render_validation_success() -> &'static str {
    "Result: valid\n"
}

fn validation_error(errors: &[String]) -> CliError {
    CliError::user(format!(
        "config validation failed with {} error(s)",
        errors.len()
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

    fn loaded_config() -> LoadedDeclarativeConfig {
        let mut cfg = LoadedDeclarativeConfig::empty();
        cfg.config_version = "2.1.0".to_string();
        cfg.schema_version = 7;
        cfg
    }

    #[test]
    fn command_helper_coverage_validation_result_json_reports_invalid_configs() {
        let payload = validation_result_json(
            std::path::Path::new("fixtures/policy-config.yaml"),
            &loaded_config(),
            &[String::from("missing pack.name")],
        );

        assert_eq!(payload["file"], "fixtures/policy-config.yaml");
        assert_eq!(payload["valid"], false);
        assert_eq!(payload["config_version"], "2.1.0");
        assert_eq!(payload["schema_version"], 7);
        assert_eq!(payload["errors"], serde_json::json!(["missing pack.name"]));
    }

    #[test]
    fn command_helper_coverage_render_validation_output_is_stable() {
        let rendered =
            render_validation_header(std::path::Path::new("policy-config.yaml"), &loaded_config());

        assert_eq!(
            rendered,
            "Validating: policy-config.yaml\nConfig version: 2.1.0\n"
        );
        assert_eq!(render_validation_success(), "Result: valid\n");
    }

    #[test]
    fn command_helper_coverage_validation_error_counts_failures() {
        let error = validation_error(&[
            String::from("first"),
            String::from("second"),
            String::from("third"),
        ]);

        assert_eq!(error.exit_code(), crate::error::EXIT_USER);
        assert!(error
            .to_string()
            .contains("config validation failed with 3 error(s)"));
    }

    #[test]
    fn validation_error_single_failure() {
        let error = validation_error(&[String::from("missing field x")]);
        assert!(error
            .to_string()
            .contains("config validation failed with 1 error(s)"));
    }

    #[test]
    fn validation_result_json_valid_config() {
        let cfg = loaded_config();
        let payload = validation_result_json(std::path::Path::new("config.yaml"), &cfg, &[]);
        assert_eq!(payload["valid"], true);
        assert_eq!(payload["errors"], serde_json::json!([]));
        assert_eq!(payload["file"], "config.yaml");
    }

    #[test]
    fn validation_result_json_multiple_errors() {
        let cfg = loaded_config();
        let payload = validation_result_json(
            std::path::Path::new("bad.yaml"),
            &cfg,
            &[String::from("e1"), String::from("e2"), String::from("e3")],
        );
        assert_eq!(payload["valid"], false);
        assert_eq!(payload["errors"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn render_validation_header_format() {
        let cfg = loaded_config();
        let header = render_validation_header(std::path::Path::new("test.yaml"), &cfg);
        assert!(header.starts_with("Validating: test.yaml\n"));
        assert!(header.contains("Config version: 2.1.0"));
    }

    #[test]
    fn args_debug_impl() {
        let args = ConfigValidateArgs {
            file: std::path::PathBuf::from("policy-config.yaml"),
            json: false,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("ConfigValidateArgs"));
        assert!(debug.contains("policy-config.yaml"));
    }

    #[test]
    fn validation_error_exit_code() {
        let error = validation_error(&[String::from("any")]);
        assert_eq!(error.exit_code(), crate::error::EXIT_USER);
    }

    #[test]
    fn render_validation_success_is_static() {
        let s = render_validation_success();
        assert_eq!(s, "Result: valid\n");
        assert_eq!(render_validation_success(), render_validation_success());
    }
}
