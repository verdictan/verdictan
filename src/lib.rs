// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

// Staged gateway integrations and control-plane seams compile incrementally.
// Hotspots such as `gateway::server` apply tighter lint scopes locally.
#![allow(dead_code)]
#![recursion_limit = "256"]
#![cfg_attr(
    test,
    allow(
        clippy::await_holding_lock,
        clippy::cloned_ref_to_slice_refs,
        clippy::collapsible_match,
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used
    )
)]

mod commands;
mod config;
mod environment_doc_reconciliation;
mod error;
mod gateway;
mod i18n;
mod instances;
mod managed;
mod mcp;
mod output;
mod persistence;
mod policy;
mod region;
mod retry;
mod runner;
mod runtime;
mod secret_key_ref;
pub mod self_update;
mod supervisor;
mod telemetry;
mod trail;

#[cfg(windows)]
mod windows_private_acl;

mod test_support {
    use std::sync::{Mutex, OnceLock};

    pub fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    pub fn set_var(key: &str, value: impl AsRef<std::ffi::OsStr>) {
        std::env::set_var(key, value)
    }

    pub fn unset_var(key: &str) {
        std::env::remove_var(key)
    }
}

mod auth {
    pub(crate) mod browser_callback;
    pub mod credential_store;
    pub mod login;
    pub mod token;
}

#[cfg(test)]
mod cli_e2e_tests;
#[cfg(test)]
pub(crate) mod testing;

mod api;

use std::ffi::OsString;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

use crate::error::CliError;

const SECRET_TOKEN_LONGS: &[&str] = &["api-token", "admin-token", "upstream-api-key"];
const TOKEN_VALIDATE_VALUE_FLAGS: &[&str] =
    &["--config", "--api-url", "--profile", "--lang", "--region"];

// The `after_help` attributes reference locale-aware catalog functions from
// `crate::i18n`.

#[derive(Debug, Parser)]
#[command(name = "verdictan")]
#[command(about = "Verdictan CLI", long_about = None)]
#[command(version)]
struct Cli {
    /// Language tag for localized output (for example, en, es, ca).
    /// Overrides the VERDICTAN_LANG environment variable and OS locale.
    #[arg(long = "lang", global = true, value_name = "TAG")]
    lang: Option<String>,

    /// Explicit region override for commands that honor a process-wide
    /// region context (for example local gateway/runtime surfaces).
    #[arg(long = "region", global = true, value_name = "REGION")]
    region: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum Command {
    /// Manage the local filesystem cache.
    Cache(commands::cache::CacheArgs),

    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    /// Configure profile-oriented CLI settings such as the default region.
    Configure(commands::configure::ConfigureArgs),

    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },

    /// Run diagnostic checks on the local environment.
    Doctor(commands::doctor::DoctorArgs),

    /// Initialize a declarative config in the current directory.
    Init(commands::init::InitArgs),

    /// Lint, test, apply, and manage declarative gateway policy configs.
    /// `eu-ai-act` is reporting-only. Use POST /verdictan/compliance/report.
    /// Do not add it to policies.chain.
    #[command(after_help = crate::i18n::policy_after_help())]
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },

    Events {
        #[command(subcommand)]
        command: EventsCommand,
    },

    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },

    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },

    /// Manage local credential resolution for gateway providers.
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
    },

    Role {
        #[command(subcommand)]
        command: RoleCommand,
    },

    Iam {
        #[command(subcommand)]
        command: IamCommand,
    },

    User {
        #[command(subcommand)]
        command: UserCommand,
    },

    Team {
        #[command(subcommand)]
        command: TeamCommand,
    },

    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },

    Control {
        #[command(subcommand)]
        command: ControlCommand,
    },

    Escalation {
        #[command(subcommand)]
        command: EscalationCommand,
    },

    Spend {
        #[command(subcommand)]
        command: SpendCommand,
    },

    /// Manage API tokens for gateway access, hosted runtimes, and integrations.
    #[command(after_help = crate::i18n::token_after_help())]
    Token {
        #[command(subcommand)]
        command: commands::token::TokenCommand,
    },

    ExportJobs {
        #[command(subcommand)]
        command: ExportJobsCommand,
    },

    /// List and configure target regions for API calls.
    Regions(commands::regions::RegionsArgs),

    #[command(after_help = crate::i18n::gateway_after_help())]
    Gateway {
        #[command(subcommand)]
        command: GatewayCommand,
    },

    /// Query, verify, and export immutable audit trail events.
    Trail {
        #[command(subcommand)]
        command: trail::TrailCommands,
    },
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum ConfigCommand {
    Validate(commands::config_validate::ConfigValidateArgs),
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum AuthCommand {
    Login(commands::auth_login::AuthLoginArgs),
    Logout(commands::auth_logout::AuthLogoutArgs),
    Token {
        #[command(subcommand)]
        command: AuthTokenCommand,
    },
    Whoami(commands::auth_whoami::AuthWhoamiArgs),
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum AuthTokenCommand {
    Create(commands::auth_token::AuthTokenCreateArgs),
    List(commands::auth_token::AuthTokenListArgs),
    Revoke(commands::auth_token::AuthTokenRevokeArgs),
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum PolicyCommand {
    Apply(commands::policy_apply::PolicyApplyArgs),
    Deploy(commands::policy_deploy::PolicyDeployArgs),
    Diff(commands::policy_diff::PolicyDiffArgs),
    Evaluate(commands::policy_evaluate::PolicyEvaluateArgs),
    Export(commands::policy_export::PolicyExportArgs),
    Lint(commands::policy_lint::PolicyLintArgs),
    Push(commands::policy_push::PolicyPushArgs),
    Test(commands::policy_test::PolicyTestArgs),
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum EventsCommand {
    Tail(commands::events_tail::EventsTailArgs),
    Export(commands::events_export::EventsExportArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::history_after_help())]
enum HistoryCommand {
    ListSessions(commands::history_list_sessions::HistoryListSessionsArgs),
    GetSession(commands::history_get_session::HistoryGetSessionArgs),
    Learn(commands::history_learn::HistoryLearnArgs),
    Condense(commands::history_condense::HistoryCondenseArgs),
    Export(commands::history_export::HistoryExportArgs),
    Tag(commands::history_tag::HistoryTagArgs),
    Search(commands::history_search::HistorySearchArgs),
    Share(commands::history_share::HistoryShareArgs),
    Replay(commands::history_replay::HistoryReplayArgs),
    Stats(commands::history_stats::HistoryStatsArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::secret_after_help())]
enum SecretCommand {
    List(commands::secret_list::SecretListArgs),
    Get(commands::secret_get::SecretGetArgs),
    Create(commands::secret_create::SecretCreateArgs),
    Update(commands::secret_update::SecretUpdateArgs),
    Delete(commands::secret_delete::SecretDeleteArgs),
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum SecretsCommand {
    /// Add a secret to the keychain or shared store.
    Add(commands::secrets_add::SecretsAddArgs),
    /// Report credential resolution status for provider targets.
    Status(commands::secrets_status::SecretsStatusArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::role_after_help())]
enum RoleCommand {
    List(commands::role_list::RoleListArgs),
    Get(commands::role_get::RoleGetArgs),
    Create(commands::role_create::RoleCreateArgs),
    Update(commands::role_update::RoleUpdateArgs),
    Delete(commands::role_delete::RoleDeleteArgs),
    AttachPolicy(commands::role_attach_policy::RoleAttachPolicyArgs),
    DetachPolicy(commands::role_detach_policy::RoleDetachPolicyArgs),
    ShowActions(commands::role_show_actions::RoleShowActionsArgs),
    ShowAssignments(commands::role_show_assignments::RoleShowAssignmentsArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::iam_after_help())]
enum IamCommand {
    Policy {
        #[command(subcommand)]
        command: IamPolicyCommand,
    },
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum IamPolicyCommand {
    List(commands::iam_policy_list::IamPolicyListArgs),
    Get(commands::iam_policy_get::IamPolicyGetArgs),
    Create(commands::iam_policy_create::IamPolicyCreateArgs),
    Update(commands::iam_policy_update::IamPolicyUpdateArgs),
    Delete(commands::iam_policy_delete::IamPolicyDeleteArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::user_after_help())]
enum UserCommand {
    List(commands::user_list::UserListArgs),
    Get(commands::user_get::UserGetArgs),
    Invite(commands::user_invite::UserInviteArgs),
    Update(commands::user_update::UserUpdateArgs),
    Suspend(commands::user_suspend::UserSuspendArgs),
    Reactivate(commands::user_reactivate::UserReactivateArgs),
    RemoveMembership(commands::user_remove_membership::UserRemoveMembershipArgs),
    AssignRole(commands::user_assign_role::UserAssignRoleArgs),
    DetachRole(commands::user_detach_role::UserDetachRoleArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::team_after_help())]
enum TeamCommand {
    List(commands::team_list::TeamListArgs),
    Get(commands::team_get::TeamGetArgs),
    Create(commands::team_create::TeamCreateArgs),
    Update(commands::team_update::TeamUpdateArgs),
    Delete(commands::team_delete::TeamDeleteArgs),
    AddMember(commands::team_add_member::TeamAddMemberArgs),
    RemoveMember(commands::team_remove_member::TeamRemoveMemberArgs),
    AssignRole(commands::team_assign_role::TeamAssignRoleArgs),
    DetachRole(commands::team_detach_role::TeamDetachRoleArgs),
    ListMembers(commands::team_list_members::TeamListMembersArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::agent_after_help())]
enum AgentCommand {
    List(commands::agent_list::AgentListArgs),
    Get(commands::agent_get::AgentGetArgs),
    Create(commands::agent_create::AgentCreateArgs),
    Update(commands::agent_update::AgentUpdateArgs),
    Delete(commands::agent_delete::AgentDeleteArgs),
    LinkGateway(commands::agent_link_gateway::AgentLinkGatewayArgs),
    UnlinkGateway(commands::agent_unlink_gateway::AgentUnlinkGatewayArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::control_after_help())]
enum ControlCommand {
    Plan(commands::control_plan::ControlPlanArgs),
    Apply(commands::control_apply::ControlApplyArgs),
    Export(commands::control_export::ControlExportArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::escalation_after_help())]
enum EscalationCommand {
    List(commands::escalation_list::EscalationListArgs),
    Get(commands::escalation_get::EscalationGetArgs),
    Claim(commands::escalation_claim::EscalationClaimArgs),
    Unclaim(commands::escalation_unclaim::EscalationUnclaimArgs),
    Resolve(commands::escalation_resolve::EscalationResolveArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::spend_after_help())]
enum SpendCommand {
    Summary(commands::spend_summary::SpendSummaryArgs),
    Budget {
        #[command(subcommand)]
        command: BudgetCommand,
    },
    ProviderBudget {
        #[command(subcommand)]
        command: ProviderBudgetCommand,
    },
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum BudgetCommand {
    List(commands::budget_list::BudgetListArgs),
    Get(commands::budget_get::BudgetGetArgs),
    Create(commands::budget_create::BudgetCreateArgs),
    Update(commands::budget_update::BudgetUpdateArgs),
    Delete(commands::budget_delete::BudgetDeleteArgs),
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum ProviderBudgetCommand {
    List(commands::provider_budget_list::ProviderBudgetListArgs),
    Get(commands::provider_budget_get::ProviderBudgetGetArgs),
    Create(commands::provider_budget_create::ProviderBudgetCreateArgs),
    Delete(commands::provider_budget_delete::ProviderBudgetDeleteArgs),
}

#[derive(Debug, Subcommand)]
#[command(after_help = crate::i18n::export_jobs_after_help())]
enum ExportJobsCommand {
    List(commands::export_job_list::ExportJobListArgs),
    Get(commands::export_job_get::ExportJobGetArgs),
    Create(commands::export_job_create::ExportJobCreateArgs),
    Download(commands::export_job_download::ExportJobDownloadArgs),
}

#[derive(Debug, Subcommand)]
#[command(disable_help_subcommand = true)]
enum GatewayCommand {
    Check(commands::gateway_check::GatewayCheckArgs),
    Config(commands::gateway_config::GatewayConfigArgs),
    Create(commands::gateway_create::GatewayCreateArgs),
    Diff(commands::gateway_diff::GatewayDiffArgs),
    Inspect(commands::gateway_inspect::GatewayInspectArgs),
    Install(commands::gateway_install::GatewayInstallArgs),
    List(commands::gateway_list::GatewayListArgs),
    Reconcile(commands::gateway_reconcile::GatewayReconcileArgs),
    Revert(commands::gateway_revert::GatewayRevertArgs),
    Reload(commands::gateway_reload::GatewayReloadArgs),
    Run(commands::gateway_run::GatewayRunArgs),
    Stop(commands::gateway_stop::GatewayStopArgs),
    Start(commands::gateway_start::GatewayStartArgs),
    Status(commands::gateway_status::GatewayStatusArgs),
    Upgrade(commands::gateway_upgrade::GatewayUpgradeArgs),
    Uninstall(commands::gateway_uninstall::GatewayUninstallArgs),
}

/// Scan raw process arguments for `--lang <tag>` or `--lang=<tag>` without
/// triggering clap. Returns the resolved locale for any explicit tag, so that
/// help rendering follows the same precedence and English fallback rules as the
/// main i18n resolver.
fn preparse_lang_arg_from(args: &[String]) -> Option<i18n::Locale> {
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--lang" {
            if let Some(tag) = args.get(i + 1) {
                return Some(i18n::resolve(Some(tag.trim())));
            }
        } else if let Some(tag) = args[i].strip_prefix("--lang=") {
            return Some(i18n::resolve(Some(tag.trim())));
        }
        i += 1;
    }
    None
}

fn preparse_lang_arg() -> Option<i18n::Locale> {
    let args: Vec<String> = std::env::args().collect();
    preparse_lang_arg_from(&args)
}

fn token_validate_positional_secret_present(raw_args: &[&str]) -> bool {
    let Some(index) = raw_args
        .windows(2)
        .position(|window| matches!(window, ["token", "validate"]))
    else {
        return false;
    };

    let mut consumes_next_value = false;
    let mut positional_only = false;

    for arg in raw_args.iter().skip(index + 2).copied() {
        if positional_only {
            return true;
        }

        if consumes_next_value {
            consumes_next_value = false;
            continue;
        }

        if arg == "--" {
            positional_only = true;
            continue;
        }

        if matches!(arg, "--json" | "--force-tty") {
            continue;
        }

        if TOKEN_VALIDATE_VALUE_FLAGS.contains(&arg) {
            consumes_next_value = true;
            continue;
        }

        if TOKEN_VALIDATE_VALUE_FLAGS.iter().any(|flag| {
            arg.len() > flag.len()
                && arg.starts_with(flag)
                && arg.as_bytes().get(flag.len()) == Some(&b'=')
        }) {
            continue;
        }

        if !arg.starts_with('-') {
            return true;
        }
    }

    false
}

fn secret_arg_error(arg: &str) -> CliError {
    match arg {
        "--upstream-api-key" => CliError::user(
            "--upstream-api-key has been removed; set VERDICTAN_UPSTREAM_API_KEY instead",
        ),
        "--api-token" | "--admin-token" | "--gateway-key" => CliError::user(
            "command-line token flags have been removed; set VERDICTAN_API_TOKEN or use a stored profile instead",
        ),
        other => CliError::user(format!(
            "{other} is not a supported secure token input; use VERDICTAN_API_TOKEN or a stored profile instead"
        )),
    }
}

const REMOVED_CUSTOMER_COMMERCE_COMMANDS: &[(&str, &str)] = &[
    (
        "wallet",
        "the wallet command has been removed; use `verdictan spend summary` and `verdictan spend budget` for cost controls",
    ),
    (
        "billing",
        "the billing command has been removed; use `verdictan spend` for usage budgets and spend summary",
    ),
    (
        "credit",
        "the credit command has been removed; customer credit management is no longer available",
    ),
    (
        "checkout",
        "the checkout command has been removed; self-service payment checkout is no longer available",
    ),
    (
        "payment",
        "the payment command has been removed; customer payment operations are no longer available",
    ),
];

fn first_command_token<'a>(raw_args: &'a [&'a str]) -> Option<&'a str> {
    let mut index = 1usize;
    while index < raw_args.len() {
        let arg = raw_args[index];
        if arg == "--" {
            return raw_args.get(index + 1).copied();
        }
        if matches!(arg, "--lang" | "--region") {
            index += 2;
            continue;
        }
        if arg.starts_with("--lang=") || arg.starts_with("--region=") {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        return Some(arg);
    }
    None
}

fn removed_customer_commerce_command_error(command: &str) -> Option<CliError> {
    REMOVED_CUSTOMER_COMMERCE_COMMANDS
        .iter()
        .find_map(|(name, message)| (*name == command).then(|| CliError::user(*message)))
}

fn reject_removed_customer_commerce_commands(args: &[OsString]) -> Result<(), CliError> {
    let raw_args = args
        .iter()
        .filter_map(|value| value.to_str())
        .collect::<Vec<_>>();
    let Some(command) = first_command_token(&raw_args) else {
        return Ok(());
    };
    if let Some(error) = removed_customer_commerce_command_error(command) {
        return Err(error);
    }
    Ok(())
}

fn reject_legacy_secret_args(args: &[OsString]) -> Result<(), CliError> {
    let raw_args = args
        .iter()
        .filter_map(|value| value.to_str())
        .collect::<Vec<_>>();

    // Pre-scan the `verdictan token validate` argv shape so clap never gets a chance
    // to echo a pasted secret back in an "unexpected argument" diagnostic.
    if token_validate_positional_secret_present(&raw_args) {
        return Err(CliError::user(
            "token validate reads the raw token from stdin; pipe it in or rerun with --force-tty",
        ));
    }

    for arg in raw_args.iter().skip(1).copied() {
        match arg {
            "--api-token" | "--admin-token" | "--gateway-key" | "--upstream-api-key" => {
                return Err(secret_arg_error(arg));
            }
            _ => {}
        }

        for prefix in [
            "--api-token=",
            "--admin-token=",
            "--gateway-key=",
            "--upstream-api-key=",
        ] {
            if arg.starts_with(prefix) {
                let flag = prefix.trim_end_matches('=');
                return Err(secret_arg_error(flag));
            }
        }
    }
    Ok(())
}

fn hide_secret_args(command: &mut clap::Command) {
    let ids = command
        .get_arguments()
        .filter_map(|arg| {
            let long = arg.get_long()?;
            SECRET_TOKEN_LONGS
                .contains(&long)
                .then(|| arg.get_id().clone())
        })
        .collect::<Vec<_>>();

    for id in ids {
        *command = command.clone().mut_arg(id, |arg| arg.hide(true));
    }

    for subcommand in command.get_subcommands_mut() {
        hide_secret_args(subcommand);
    }
}

fn parse_cli() -> Result<Option<Cli>, CliError> {
    let raw_args = std::env::args_os().collect::<Vec<_>>();
    reject_removed_customer_commerce_commands(&raw_args)?;
    reject_legacy_secret_args(&raw_args)?;

    let mut command = Cli::command();
    hide_secret_args(&mut command);

    let matches = match command.try_get_matches_from(raw_args) {
        Ok(matches) => matches,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            print!("{error}");
            return Ok(None);
        }
        Err(error) => {
            return Err(CliError::user(error.to_string()));
        }
    };

    let cli = Cli::from_arg_matches(&matches)
        .map_err(|error| CliError::internal(format!("failed to decode clap matches: {error}")))?;
    Ok(Some(cli))
}

pub fn entrypoint() -> i32 {
    match run() {
        Ok(()) => error::EXIT_SUCCESS,
        Err(err) => {
            let code = err.exit_code();
            eprintln!("{}", err);
            code
        }
    }
}

/// Library entry point for the CLI.
///
/// Parses arguments, initialises telemetry, and dispatches the requested
/// command.  Returns `Ok(())` on success or a typed [`CliError`] on failure.
///
/// This is the testable seam — integration tests can call `verdictan_cli::run()`
/// directly without going through `main()` and `std::process::exit`.
pub fn run() -> Result<(), CliError> {
    // If --lang was passed on the command line, apply it before Cli::parse()
    // so that after_help strings and all subsequent runtime output use the
    // requested locale.  preparse_lang_arg() scans raw args without triggering
    // clap, so it works even for `--help` invocations.
    if let Some(locale) = preparse_lang_arg() {
        i18n::override_global(locale);
    }
    // Initialise from VERDICTAN_LANG / OS env when --lang was not supplied.
    // This is a no-op if override_global already populated the OnceLock.
    i18n::init_global_from_env();

    let Some(cli) = parse_cli()? else {
        return Ok(());
    };
    // --lang was already applied via preparse_lang_arg(); no further action.

    if let Some(ref region) = cli.region {
        // Preserve the top-level `verdictan --region ...` shim for commands that still
        // read process-wide region context. Explicit config/API region
        // resolution no longer falls back to VERDICTAN_REGION.
        std::env::set_var("VERDICTAN_REGION", region);
    }

    // ── Single runtime per process ────────────────────────────────────────
    // Determine runtime requirements from the matched command before building
    // anything.  Gateway run and gateway start need multi-thread; the MCP
    // server manages its own runtime internally; purely-sync commands skip
    // runtime creation entirely.
    let is_gateway_run = matches!(
        &cli.command,
        Command::Gateway {
            command: GatewayCommand::Run(_)
        }
    );
    let is_gateway_start = matches!(
        &cli.command,
        Command::Gateway {
            command: GatewayCommand::Start(_)
        }
    );

    // ── Lazy telemetry init ───────────────────────────────────────────────
    // Simple commands get a minimal stderr-only subscriber; gateway run
    // defers telemetry to its own async startup; everything else gets the
    // standard fmt subscriber without OTLP.
    let is_minimal_telemetry = matches!(
        &cli.command,
        Command::Config {
            command: ConfigCommand::Validate(_)
        } | Command::Configure(_)
            | Command::Policy {
                command: PolicyCommand::Lint(_)
            }
            | Command::Init(_)
            | Command::Doctor(_)
            | Command::Regions(_)
    );

    if !is_gateway_run && !is_gateway_start {
        if is_minimal_telemetry {
            telemetry::init_minimal()?;
        } else {
            telemetry::init(false)?;
        }
    }

    // Sync-only commands: no runtime needed, dispatch directly.
    if is_sync_command(&cli.command) {
        return dispatch_sync(cli.command);
    }

    // Gateway run / start have their own multi-thread runtimes managed
    // inside the command module (they call telemetry::init(true) internally).
    if is_gateway_run || is_gateway_start {
        return dispatch_own_runtime(cli.command);
    }

    // All remaining commands share a single current-thread Tokio runtime.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::internal(format!("failed to build tokio runtime: {e}")))?;

    rt.block_on(dispatch_async(cli.command))
}

/// Returns `true` for commands that require no Tokio runtime at all.
fn is_sync_command(command: &Command) -> bool {
    matches!(
        command,
        Command::Cache(_)
            | Command::Config {
                command: ConfigCommand::Validate(_)
            }
            | Command::Configure(_)
            | Command::Auth {
                command: AuthCommand::Logout(_)
            }
            | Command::Policy {
                command: PolicyCommand::Lint(_)
            }
            | Command::Secrets { .. }
            | Command::Gateway {
                command: GatewayCommand::Check(_)
                    | GatewayCommand::Create(_)
                    | GatewayCommand::Diff(_)
                    | GatewayCommand::Inspect(_)
                    | GatewayCommand::Install(_)
                    | GatewayCommand::Status(_)
                    | GatewayCommand::Stop(_)
                    | GatewayCommand::Uninstall(_)
            }
    )
}

/// Dispatch for purely synchronous commands (no Tokio runtime).
fn dispatch_sync(command: Command) -> Result<(), CliError> {
    match command {
        Command::Cache(args) => commands::cache::run(args),
        Command::Config { command } => match command {
            ConfigCommand::Validate(args) => commands::config_validate::run(args),
        },
        Command::Configure(args) => commands::configure::run(args),
        Command::Auth {
            command: AuthCommand::Logout(args),
        } => commands::auth_logout::run(args),
        Command::Policy {
            command: PolicyCommand::Lint(args),
        } => commands::policy_lint::run(args),
        Command::Secrets { command } => match command {
            SecretsCommand::Add(args) => commands::secrets_add::run(args),
            SecretsCommand::Status(args) => commands::secrets_status::run(args),
        },
        Command::Gateway { command } => match command {
            GatewayCommand::Check(args) => commands::gateway_check::run(args),
            GatewayCommand::Create(args) => commands::gateway_create::run(args),
            GatewayCommand::Diff(args) => commands::gateway_diff::run(args),
            GatewayCommand::Inspect(args) => commands::gateway_inspect::run(args),
            GatewayCommand::Install(args) => commands::gateway_install::run(args),
            GatewayCommand::Status(args) => commands::gateway_status::run(args),
            GatewayCommand::Stop(args) => commands::gateway_stop::run(args),
            GatewayCommand::Uninstall(args) => commands::gateway_uninstall::run(args),
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

/// Dispatch for commands that manage their own Tokio runtime internally
/// (gateway run, gateway start).
fn dispatch_own_runtime(command: Command) -> Result<(), CliError> {
    match command {
        Command::Gateway {
            command: GatewayCommand::Run(args),
        } => commands::gateway_run::run(args),
        Command::Gateway {
            command: GatewayCommand::Start(args),
        } => commands::gateway_start::run(args),
        _ => unreachable!(),
    }
}

/// Async dispatch for all commands that share the centralized runtime.
async fn dispatch_async(command: Command) -> Result<(), CliError> {
    match command {
        Command::Auth { command } => match command {
            AuthCommand::Login(args) => commands::auth_login::run_async(args).await,
            AuthCommand::Token { command } => match command {
                AuthTokenCommand::Create(args) => {
                    commands::auth_token::run_create_async(args).await
                }
                AuthTokenCommand::List(args) => commands::auth_token::run_list_async(args).await,
                AuthTokenCommand::Revoke(args) => {
                    commands::auth_token::run_revoke_async(args).await
                }
            },
            AuthCommand::Whoami(args) => commands::auth_whoami::run_async(args).await,
            _ => unreachable!(),
        },

        Command::Doctor(args) => commands::doctor::run_async(args).await,

        Command::Init(args) => commands::init::run_async(args).await,

        Command::Policy { command } => match command {
            PolicyCommand::Apply(args) => commands::policy_apply::run_async(args).await,
            PolicyCommand::Deploy(args) => commands::policy_deploy::run_async(args).await,
            PolicyCommand::Diff(args) => commands::policy_diff::run_async(args).await,
            PolicyCommand::Evaluate(args) => commands::policy_evaluate::run_async(args).await,
            PolicyCommand::Export(args) => commands::policy_export::run_async(args).await,
            PolicyCommand::Push(args) => commands::policy_push::run_async(args).await,
            PolicyCommand::Test(args) => commands::policy_test::run_async(args).await,
            _ => unreachable!(),
        },

        Command::Events { command } => match command {
            EventsCommand::Tail(args) => commands::events_tail::run_async(args).await,
            EventsCommand::Export(args) => commands::events_export::run_async(args).await,
        },

        Command::History { command } => dispatch_history_async(command).await,

        Command::Secret { command } => dispatch_secret_async(command).await,

        Command::Role { command } => dispatch_role_async(command).await,

        Command::Iam { command } => dispatch_iam_async(command).await,

        Command::User { command } => dispatch_user_async(command).await,

        Command::Team { command } => dispatch_team_async(command).await,

        Command::Agent { command } => dispatch_agent_async(command).await,

        Command::Control { command } => dispatch_control_async(command).await,

        Command::Escalation { command } => dispatch_escalation_async(command).await,

        Command::Spend { command } => dispatch_spend_async(command).await,

        Command::Token { command } => dispatch_token_async(command).await,

        Command::ExportJobs { command } => dispatch_export_jobs_async(command).await,

        Command::Regions(args) => match args.command.clone() {
            commands::regions::RegionsCommand::List {
                enabled,
                disabled,
                group,
                sovereignty_class,
            } => {
                commands::regions::run_list_async(
                    args,
                    commands::regions::RegionListFilters {
                        enabled,
                        disabled,
                        group,
                        sovereignty_class,
                    },
                )
                .await
            }
            commands::regions::RegionsCommand::Status => {
                commands::regions::run_status_async(args).await
            }
            commands::regions::RegionsCommand::Use { region } => {
                let config_path = args.config.clone();
                let profile = args.profile.clone();
                commands::regions::run_use(config_path, profile, region)
            }
            commands::regions::RegionsCommand::Switch { region } => {
                let config_path = args.config.clone();
                let profile = args.profile.clone();
                commands::regions::run_use(config_path, profile, region)
            }
            commands::regions::RegionsCommand::Current => commands::regions::run(args),
        },

        Command::Gateway { command } => dispatch_gateway_async(command).await,

        Command::Trail { command } => dispatch_trail_async(command).await,

        _ => unreachable!(),
    }
}

async fn dispatch_gateway_async(command: GatewayCommand) -> Result<(), CliError> {
    match command {
        GatewayCommand::Config(args) => commands::gateway_config::run_async(args).await,
        GatewayCommand::List(args) => commands::gateway_list::run_async(args).await,
        GatewayCommand::Reconcile(args) => commands::gateway_reconcile::run_async(args).await,
        GatewayCommand::Revert(args) => commands::gateway_revert::run_async(args).await,
        GatewayCommand::Reload(args) => commands::gateway_reload::run_async(args).await,
        GatewayCommand::Upgrade(args) => commands::gateway_upgrade::run_async(args).await,
        _ => unreachable!(),
    }
}

async fn dispatch_history_async(command: HistoryCommand) -> Result<(), CliError> {
    match command {
        HistoryCommand::ListSessions(args) => {
            commands::history_list_sessions::run_async(args).await
        }
        HistoryCommand::GetSession(args) => commands::history_get_session::run_async(args).await,
        HistoryCommand::Learn(args) => commands::history_learn::run_async(args).await,
        HistoryCommand::Condense(args) => commands::history_condense::run_async(args).await,
        HistoryCommand::Export(args) => commands::history_export::run_async(args).await,
        HistoryCommand::Tag(args) => commands::history_tag::run_async(args).await,
        HistoryCommand::Search(args) => commands::history_search::run_async(args).await,
        HistoryCommand::Share(args) => commands::history_share::run_async(args).await,
        HistoryCommand::Replay(args) => commands::history_replay::run_async(args).await,
        HistoryCommand::Stats(args) => commands::history_stats::run_async(args).await,
    }
}

async fn dispatch_secret_async(command: SecretCommand) -> Result<(), CliError> {
    match command {
        SecretCommand::List(args) => commands::secret_list::run_async(args).await,
        SecretCommand::Get(args) => commands::secret_get::run_async(args).await,
        SecretCommand::Create(args) => commands::secret_create::run_async(args).await,
        SecretCommand::Update(args) => commands::secret_update::run_async(args).await,
        SecretCommand::Delete(args) => commands::secret_delete::run_async(args).await,
    }
}

async fn dispatch_role_async(command: RoleCommand) -> Result<(), CliError> {
    match command {
        RoleCommand::List(args) => commands::role_list::run_async(args).await,
        RoleCommand::Get(args) => commands::role_get::run_async(args).await,
        RoleCommand::Create(args) => commands::role_create::run_async(args).await,
        RoleCommand::Update(args) => commands::role_update::run_async(args).await,
        RoleCommand::Delete(args) => commands::role_delete::run_async(args).await,
        RoleCommand::AttachPolicy(args) => commands::role_attach_policy::run_async(args).await,
        RoleCommand::DetachPolicy(args) => commands::role_detach_policy::run_async(args).await,
        RoleCommand::ShowActions(args) => commands::role_show_actions::run_async(args).await,
        RoleCommand::ShowAssignments(args) => {
            commands::role_show_assignments::run_async(args).await
        }
    }
}

async fn dispatch_iam_async(command: IamCommand) -> Result<(), CliError> {
    match command {
        IamCommand::Policy { command } => match command {
            IamPolicyCommand::List(args) => commands::iam_policy_list::run_async(args).await,
            IamPolicyCommand::Get(args) => commands::iam_policy_get::run_async(args).await,
            IamPolicyCommand::Create(args) => commands::iam_policy_create::run_async(args).await,
            IamPolicyCommand::Update(args) => commands::iam_policy_update::run_async(args).await,
            IamPolicyCommand::Delete(args) => commands::iam_policy_delete::run_async(args).await,
        },
    }
}

async fn dispatch_user_async(command: UserCommand) -> Result<(), CliError> {
    match command {
        UserCommand::List(args) => commands::user_list::run_async(args).await,
        UserCommand::Get(args) => commands::user_get::run_async(args).await,
        UserCommand::Invite(args) => commands::user_invite::run_async(args).await,
        UserCommand::Update(args) => commands::user_update::run_async(args).await,
        UserCommand::Suspend(args) => commands::user_suspend::run_async(args).await,
        UserCommand::Reactivate(args) => commands::user_reactivate::run_async(args).await,
        UserCommand::RemoveMembership(args) => {
            commands::user_remove_membership::run_async(args).await
        }
        UserCommand::AssignRole(args) => commands::user_assign_role::run_async(args).await,
        UserCommand::DetachRole(args) => commands::user_detach_role::run_async(args).await,
    }
}

async fn dispatch_team_async(command: TeamCommand) -> Result<(), CliError> {
    match command {
        TeamCommand::List(args) => commands::team_list::run_async(args).await,
        TeamCommand::Get(args) => commands::team_get::run_async(args).await,
        TeamCommand::Create(args) => commands::team_create::run_async(args).await,
        TeamCommand::Update(args) => commands::team_update::run_async(args).await,
        TeamCommand::Delete(args) => commands::team_delete::run_async(args).await,
        TeamCommand::AddMember(args) => commands::team_add_member::run_async(args).await,
        TeamCommand::RemoveMember(args) => commands::team_remove_member::run_async(args).await,
        TeamCommand::AssignRole(args) => commands::team_assign_role::run_async(args).await,
        TeamCommand::DetachRole(args) => commands::team_detach_role::run_async(args).await,
        TeamCommand::ListMembers(args) => commands::team_list_members::run_async(args).await,
    }
}

async fn dispatch_agent_async(command: AgentCommand) -> Result<(), CliError> {
    match command {
        AgentCommand::List(args) => commands::agent_list::run_async(args).await,
        AgentCommand::Get(args) => commands::agent_get::run_async(args).await,
        AgentCommand::Create(args) => commands::agent_create::run_async(args).await,
        AgentCommand::Update(args) => commands::agent_update::run_async(args).await,
        AgentCommand::Delete(args) => commands::agent_delete::run_async(args).await,
        AgentCommand::LinkGateway(args) => commands::agent_link_gateway::run_async(args).await,
        AgentCommand::UnlinkGateway(args) => commands::agent_unlink_gateway::run_async(args).await,
    }
}

async fn dispatch_control_async(command: ControlCommand) -> Result<(), CliError> {
    match command {
        ControlCommand::Plan(args) => commands::control_plan::run_async(args).await,
        ControlCommand::Apply(args) => commands::control_apply::run_async(args).await,
        ControlCommand::Export(args) => commands::control_export::run_async(args).await,
    }
}

async fn dispatch_escalation_async(command: EscalationCommand) -> Result<(), CliError> {
    match command {
        EscalationCommand::List(args) => commands::escalation_list::run_async(args).await,
        EscalationCommand::Get(args) => commands::escalation_get::run_async(args).await,
        EscalationCommand::Claim(args) => commands::escalation_claim::run_async(args).await,
        EscalationCommand::Unclaim(args) => commands::escalation_unclaim::run_async(args).await,
        EscalationCommand::Resolve(args) => commands::escalation_resolve::run_async(args).await,
    }
}

async fn dispatch_spend_async(command: SpendCommand) -> Result<(), CliError> {
    match command {
        SpendCommand::Summary(args) => commands::spend_summary::run_async(args).await,
        SpendCommand::Budget { command } => match command {
            BudgetCommand::List(args) => commands::budget_list::run_async(args).await,
            BudgetCommand::Get(args) => commands::budget_get::run_async(args).await,
            BudgetCommand::Create(args) => commands::budget_create::run_async(args).await,
            BudgetCommand::Update(args) => commands::budget_update::run_async(args).await,
            BudgetCommand::Delete(args) => commands::budget_delete::run_async(args).await,
        },
        SpendCommand::ProviderBudget { command } => match command {
            ProviderBudgetCommand::List(args) => {
                commands::provider_budget_list::run_async(args).await
            }
            ProviderBudgetCommand::Get(args) => {
                commands::provider_budget_get::run_async(args).await
            }
            ProviderBudgetCommand::Create(args) => {
                commands::provider_budget_create::run_async(args).await
            }
            ProviderBudgetCommand::Delete(args) => {
                commands::provider_budget_delete::run_async(args).await
            }
        },
    }
}

async fn dispatch_token_async(command: commands::token::TokenCommand) -> Result<(), CliError> {
    use commands::token::TokenCommand;
    match command {
        TokenCommand::List(args) => commands::token::run_list_async(args).await,
        TokenCommand::Get(args) => commands::token::run_get_async(args).await,
        TokenCommand::Create(args) => commands::token::run_create_async(args).await,
        TokenCommand::Update(args) => commands::token::run_update_async(args).await,
        TokenCommand::Clone(args) => commands::token::run_clone_async(args).await,
        TokenCommand::EmergencyRevoke(args) => {
            commands::token::run_emergency_revoke_async(args).await
        }
        TokenCommand::Delete(args) => commands::token::run_delete_async(args).await,
        TokenCommand::Rotate(args) => commands::token::run_rotate_async(args).await,
        TokenCommand::Validate(args) => commands::token::run_validate_async(args).await,
        TokenCommand::ExchangeCode(args) => commands::token_exchange_code::run_async(args).await,
    }
}

async fn dispatch_export_jobs_async(command: ExportJobsCommand) -> Result<(), CliError> {
    match command {
        ExportJobsCommand::List(args) => commands::export_job_list::run_async(args).await,
        ExportJobsCommand::Get(args) => commands::export_job_get::run_async(args).await,
        ExportJobsCommand::Create(args) => commands::export_job_create::run_async(args).await,
        ExportJobsCommand::Download(args) => commands::export_job_download::run_async(args).await,
    }
}

async fn dispatch_trail_async(command: trail::TrailCommands) -> Result<(), CliError> {
    match command {
        trail::TrailCommands::Verify(args) => trail::verify::run_async(args).await,
        trail::TrailCommands::Lookup(args) => trail::lookup::run_async(args).await,
        trail::TrailCommands::Export(args) => trail::export::run_async(args).await,
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
    use super::{test_support, Cli};
    use crate::i18n::Locale;
    use clap::{CommandFactory, Parser};
    use serde_json::{json, Value};

    fn detect_language_summary(text: &str) -> Option<Value> {
        crate::gateway::language::detect(text).map(|result| {
            json!({
                "language": result.language,
                "confidence": result.confidence,
            })
        })
    }

    fn lint_yaml_string(yaml: &str) -> Vec<String> {
        let value: serde_yaml::Value = match serde_yaml::from_str(yaml) {
            Ok(v) => v,
            Err(e) => return vec![format!("YAML parse error: {e}")],
        };
        let json_value = match serde_json::to_value(value) {
            Ok(v) => v,
            Err(e) => return vec![format!("JSON conversion error: {e}")],
        };
        match crate::policy::lint::lint_json_value_for_test(&json_value) {
            Ok(result) => result.errors,
            Err(e) => vec![format!("lint error: {e}")],
        }
    }

    fn evaluate_citation_policy_json(
        request_json: Value,
        upstream_json: Value,
        policy_cfg: Value,
    ) -> Result<Value, String> {
        let rt = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
        let upstream_bytes =
            serde_json::to_vec(&upstream_json).map_err(|error| error.to_string())?;
        let eval = rt
            .block_on(crate::gateway::citation::evaluate_citation_verifier(
                &request_json,
                &upstream_bytes,
                &policy_cfg,
            ))
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "policy_result": eval.policy_result,
            "should_block": eval.should_block,
        }))
    }

    fn assert_ste_help_text(text: &str) {
        let lowercase = text.to_ascii_lowercase();
        assert!(
            !lowercase.contains(';'),
            "help contains a semicolon: {text}"
        );
        assert!(!lowercase.contains("e.g."), "help contains e.g.: {text}");
        assert!(!lowercase.contains("i.e."), "help contains i.e.: {text}");

        let disallowed = [
            "any", "required", "require", "requires", "need", "needs", "once", "both", "either",
            "already", "still", "never", "present", "intended", "valid", "instead",
        ];
        for word in lowercase.split(|character: char| {
            !character.is_ascii_alphanumeric() && character != '_' && character != '-'
        }) {
            assert!(
                !disallowed.contains(&word),
                "help contains a non-STE construction '{word}': {text}"
            );
        }
    }

    fn assert_command_help_is_ste(command: &clap::Command) {
        if let Some(about) = command.get_about() {
            assert_ste_help_text(&about.to_string());
        }
        if let Some(about) = command.get_long_about() {
            assert_ste_help_text(&about.to_string());
        }
        for argument in command.get_arguments() {
            if let Some(help) = argument.get_help() {
                assert_ste_help_text(&help.to_string());
            }
            if let Some(help) = argument.get_long_help() {
                assert_ste_help_text(&help.to_string());
            }
        }
        for subcommand in command.get_subcommands() {
            assert_command_help_is_ste(subcommand);
        }
    }

    #[test]
    fn clap_command_and_argument_help_uses_ste_constructions() {
        assert_command_help_is_ste(&Cli::command());
    }

    #[test]
    fn test_support_set_and_unset_var_round_trip() {
        let _guard = test_support::env_lock().lock().expect("env lock");
        test_support::unset_var("VERDICTAN_LIB_TEST_VAR");
        test_support::set_var("VERDICTAN_LIB_TEST_VAR", "value");
        assert_eq!(
            std::env::var("VERDICTAN_LIB_TEST_VAR").ok().as_deref(),
            Some("value")
        );
        test_support::unset_var("VERDICTAN_LIB_TEST_VAR");
        assert!(std::env::var("VERDICTAN_LIB_TEST_VAR").is_err());
    }

    #[test]
    fn env_lock_is_reentrant_across_tests() {
        let _guard = test_support::env_lock().lock().expect("env lock");
        assert!(test_support::env_lock().try_lock().is_err());
    }

    #[test]
    fn preparse_lang_arg_from_parses_recognized_flag_values() {
        let args = vec![
            "verdictan".to_string(),
            "--lang".to_string(),
            "es".to_string(),
            "gateway".to_string(),
            "--help".to_string(),
        ];

        assert_eq!(super::preparse_lang_arg_from(&args), Some(Locale::Es));
    }

    #[test]
    fn preparse_lang_arg_from_defaults_invalid_flag_values_to_english() {
        let args = vec![
            "verdictan".to_string(),
            "--lang=fr".to_string(),
            "gateway".to_string(),
            "--help".to_string(),
        ];

        assert_eq!(super::preparse_lang_arg_from(&args), Some(Locale::En));
    }

    #[test]
    fn preparse_lang_arg_from_ignores_missing_flag() {
        let args = vec![
            "verdictan".to_string(),
            "gateway".to_string(),
            "--help".to_string(),
        ];

        assert_eq!(super::preparse_lang_arg_from(&args), None);
    }

    #[test]
    fn detect_language_summary_handles_empty_and_unicode_scripts() {
        assert!(detect_language_summary("").is_none());

        let summary = detect_language_summary("مرحبا بالعالم").expect("arabic summary");
        assert_eq!(summary["language"], "ar");
        assert!(summary["confidence"].as_f64().unwrap_or_default() > 0.0);
    }

    #[test]
    fn lint_yaml_string_reports_parse_errors() {
        let diagnostics = lint_yaml_string("pack: [");
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("YAML parse error"));
    }

    #[test]
    fn resolve_runtime_returns_none_for_unknown_provider() {
        assert!(crate::gateway::runtimes::resolve_runtime_for_target(
            "totally-unknown-provider",
            None
        )
        .is_none());
    }

    #[test]
    fn evaluate_citation_policy_json_blocks_unverified_output() {
        let request = json!({});
        let upstream = json!({
            "choices": [{
                "message": {
                    "content": "Unsupported claim without citations or evidence."
                }
            }]
        });
        let policy = json!({
            "require_sources": true,
            "rag_context": {
                "verify_against_context": false
            },
            "output_action": {
                "unverified_action": "block"
            }
        });

        let result =
            evaluate_citation_policy_json(request, upstream, policy).expect("citation evaluation");
        assert_eq!(result["should_block"], true);
        assert_eq!(
            result["policy_result"]["reason_code"],
            "citation.unverified"
        );
    }

    fn assert_denies_removed_command(argv: &[&str], command: &str) {
        let args = argv
            .iter()
            .map(|arg| std::ffi::OsString::from(*arg))
            .collect::<Vec<_>>();
        let error = super::reject_removed_customer_commerce_commands(&args)
            .expect_err("removed command should be denied");
        let message = error.to_string();
        assert!(
            message.contains(command),
            "expected denial for {command}, got: {message}"
        );
        assert!(
            message.contains("has been removed"),
            "expected removal message, got: {message}"
        );
    }

    #[test]
    fn denies_removed_wallet_command() {
        assert_denies_removed_command(&["verdictan", "wallet", "list"], "wallet");
    }

    #[test]
    fn denies_removed_billing_command() {
        assert_denies_removed_command(&["verdictan", "billing", "invoices"], "billing");
    }

    #[test]
    fn denies_removed_credit_command() {
        assert_denies_removed_command(&["verdictan", "credit", "list"], "credit");
    }

    #[test]
    fn denies_removed_checkout_command() {
        assert_denies_removed_command(&["verdictan", "checkout", "create"], "checkout");
    }

    #[test]
    fn denies_removed_payment_command() {
        assert_denies_removed_command(&["verdictan", "payment", "list"], "payment");
    }

    #[test]
    fn evaluate_citation_policy_json_accepts_valid_case_law_reference() {
        let request = json!({});
        let upstream = json!({
            "choices": [{
                "message": {
                    "content": "Brown v. Board remains foundational at 347 U.S. 483."
                }
            }]
        });
        let policy = json!({
            "require_sources": true,
            "rag_context": {
                "verify_against_context": false
            },
            "extract_patterns": ["case_law"],
            "output_action": {
                "unverified_action": "block"
            }
        });

        let result =
            evaluate_citation_policy_json(request, upstream, policy).expect("citation evaluation");
        assert_eq!(result["should_block"], false);
        assert_eq!(result["policy_result"]["reason_code"], "citation.verified");
    }
}
