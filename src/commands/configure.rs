// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

use crate::auth::credential_store;
use crate::config::sources;
use crate::error::CliError;
use crate::persistence::atomic_write;
use crate::region::validate_region_slug;

#[derive(Debug, Args)]
pub struct ConfigureArgs {
    #[command(subcommand)]
    pub command: ConfigureCommand,

    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ConfigureCommand {
    Set {
        #[command(subcommand)]
        command: ConfigureSetCommand,
    },
    Get {
        #[command(subcommand)]
        command: ConfigureGetCommand,
    },
    ListProfiles,
}

#[derive(Debug, Subcommand)]
pub enum ConfigureSetCommand {
    Region {
        region: String,
        #[arg(long, default_value = "default")]
        profile: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigureGetCommand {
    Region {
        #[arg(long, default_value = "default")]
        profile: String,
    },
}

pub fn run(args: ConfigureArgs) -> Result<(), CliError> {
    match args.command {
        ConfigureCommand::Set { command } => match command {
            ConfigureSetCommand::Region { region, profile } => {
                let path = write_profile_region(args.config, &profile, &region)?;
                println!(
                    "Configured region set to '{region}' for profile '{profile}' in {}",
                    path.display()
                );
                Ok(())
            }
        },
        ConfigureCommand::Get { command } => match command {
            ConfigureGetCommand::Region { profile } => {
                match get_profile_region(args.config.as_deref(), &profile)? {
                    Some(region) => {
                        println!("{region}");
                        Ok(())
                    }
                    None => Err(CliError::user(format!(
                        "no region configured for profile '{profile}'"
                    ))),
                }
            }
        },
        ConfigureCommand::ListProfiles => {
            let profiles = list_profiles(args.config.as_deref())?;
            for profile in profiles {
                println!("{profile}");
            }
            Ok(())
        }
    }
}

pub(crate) fn write_profile_region(
    config_path_flag: Option<PathBuf>,
    profile: &str,
    region: &str,
) -> Result<PathBuf, CliError> {
    let profile = normalize_profile_name(profile)?;
    let region = region.trim();
    if region.is_empty() {
        return Err(CliError::user("region key is required"));
    }
    validate_region_slug(region)?;

    let config_path = resolve_config_path_for_write(config_path_flag)?;
    let mut root = load_root_mapping_for_write(&config_path)?;
    upsert_profile_region(&mut root, &profile, region)?;
    write_root_mapping(&config_path, &root)?;
    Ok(config_path)
}

pub(crate) fn get_profile_region(
    config_path: Option<&Path>,
    profile: &str,
) -> Result<Option<String>, CliError> {
    let profile = normalize_profile_name(profile)?;
    let config = sources::load_profile_region_config(config_path, &profile)?;
    Ok(config
        .profile_default_region
        .or(config.legacy_default_region))
}

pub(crate) fn list_profiles(config_path: Option<&Path>) -> Result<Vec<String>, CliError> {
    let mut profiles = BTreeSet::new();
    profiles.insert("default".to_string());

    for profile in sources::list_config_profiles(config_path)? {
        profiles.insert(profile);
    }
    for profile in credential_store::list_profiles()? {
        profiles.insert(profile);
    }

    Ok(profiles.into_iter().collect())
}

pub(crate) fn resolve_config_path_for_write(
    config_path_flag: Option<PathBuf>,
) -> Result<PathBuf, CliError> {
    if let Some(path) = config_path_flag {
        return Ok(path);
    }

    if let Some(path) = std::env::var_os("VERDICTAN_CONFIG").map(PathBuf::from) {
        return Ok(path);
    }

    if let Some(path) = sources::default_config_path() {
        return Ok(path);
    }

    let home = std::env::var_os("VERDICTAN_TEST_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .ok_or_else(|| CliError::user("unable to determine config path"))?;
    Ok(home.join(".verdictan").join("config.yaml"))
}

fn normalize_profile_name(profile: &str) -> Result<String, CliError> {
    let profile = profile.trim();
    if profile.is_empty() {
        return Err(CliError::user("profile name is required"));
    }
    Ok(profile.to_string())
}

fn load_root_mapping_for_write(path: &Path) -> Result<serde_yaml::Mapping, CliError> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(serde_yaml::Mapping::new());
        }
        Err(err) => {
            return Err(CliError::user(format!(
                "failed to read config file {}: {err}",
                path.display()
            )));
        }
    };

    let value: serde_yaml::Value = serde_yaml::from_str(&contents).map_err(|err| {
        CliError::user(format!(
            "config file {} is not valid YAML: {err}",
            path.display()
        ))
    })?;

    match value {
        serde_yaml::Value::Mapping(mapping) => {
            reject_legacy_api_key(&mapping)?;
            Ok(mapping)
        }
        serde_yaml::Value::Null => Ok(serde_yaml::Mapping::new()),
        _ => Err(CliError::user(format!(
            "config file {} must contain a top-level mapping",
            path.display()
        ))),
    }
}

fn reject_legacy_api_key(root: &serde_yaml::Mapping) -> Result<(), CliError> {
    let api_key = root
        .get(serde_yaml::Value::String("api_key".to_string()))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if api_key.is_some() {
        return Err(CliError::user(
            "config file api_key has been removed; use api_token or `verdictan auth login`. For provider configs, use secret_key_ref with a config-variable name",
        ));
    }

    Ok(())
}

fn upsert_profile_region(
    root: &mut serde_yaml::Mapping,
    profile: &str,
    region: &str,
) -> Result<(), CliError> {
    let profiles_key = serde_yaml::Value::String("profiles".to_string());
    let profile_key = serde_yaml::Value::String(profile.to_string());
    let default_region_key = serde_yaml::Value::String("default_region".to_string());

    let profiles_value = root
        .entry(profiles_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let profiles_map = profiles_value.as_mapping_mut().ok_or_else(|| {
        CliError::user("config file field 'profiles' must be a mapping when present")
    })?;

    let profile_value = profiles_map
        .entry(profile_key)
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    let profile_map = profile_value.as_mapping_mut().ok_or_else(|| {
        CliError::user("config file profile entries must be mappings when present")
    })?;

    profile_map.insert(
        default_region_key,
        serde_yaml::Value::String(region.to_string()),
    );
    Ok(())
}

fn write_root_mapping(path: &Path, root: &serde_yaml::Mapping) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            CliError::user(format!(
                "failed to create config directory {}: {err}",
                parent.display()
            ))
        })?;
    }

    let contents = serde_yaml::to_string(root)
        .map_err(|err| CliError::internal(format!("failed to render config yaml: {err}")))?;
    atomic_write(path, contents.as_bytes())
        .map_err(|err| CliError::user(format!("failed to write config {}: {err}", path.display())))
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
    fn upsert_profile_region_creates_nested_profiles_mapping() {
        let mut root = serde_yaml::Mapping::new();
        upsert_profile_region(&mut root, "workspace", "eu-west").expect("upsert");

        let profiles = root
            .get(serde_yaml::Value::String("profiles".to_string()))
            .and_then(|value| value.as_mapping())
            .expect("profiles mapping");
        let workspace = profiles
            .get(serde_yaml::Value::String("workspace".to_string()))
            .and_then(|value| value.as_mapping())
            .expect("workspace mapping");
        assert_eq!(
            workspace
                .get(serde_yaml::Value::String("default_region".to_string()))
                .and_then(|value| value.as_str()),
            Some("eu-west")
        );
    }

    #[test]
    fn list_profiles_includes_default_without_config_or_credentials() {
        let profiles = list_profiles(None).expect("profiles");
        assert_eq!(profiles, vec!["default".to_string()]);
    }
}
