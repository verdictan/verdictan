// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan token` — unified API token management.
//!
//! Replaces the split `access-key` and `gateway-key` command groups with a
//! single `verdictan token` surface. All tokens are managed through `/v1/tokens`.

use std::io::{self, IsTerminal, Read};

use clap::{Args, Subcommand, ValueEnum};
use serde_json::{Map, Value};

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

// ─── Shared connection args ──────────────────────────────────────────────────

#[derive(Debug, Args, Clone)]
pub(crate) struct ConnectArgs {
    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    #[arg(long)]
    pub(crate) api_url: Option<String>,

    #[arg(long, default_value = "default")]
    pub(crate) profile: String,
}

fn build_client(conn: &ConnectArgs) -> Result<(Config, AsyncApiClient), CliError> {
    let inputs = ConfigInputs {
        api_url_flag: conn.api_url.clone(),
        api_token_flag: None,
        config_path: conn.config.clone(),
        profile_flag: Some(conn.profile.clone()),
        region_flag: None,
    };
    let config = Config::resolve(inputs)?;
    let api_token = config.api_token.clone().ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    let client = AsyncApiClient::new(config.api_url.clone(), api_token)?;
    Ok((config, client))
}
// ─── Purpose enum ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum TokenPurpose {
    General,
    GatewayRuntime,
    Integration,
}

impl TokenPurpose {
    fn as_str(&self) -> &'static str {
        match self {
            Self::General => "general",
            Self::GatewayRuntime => "gateway_runtime",
            Self::Integration => "integration",
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum TokenKeyClass {
    Durable,
    Virtual,
    Disposable,
}

impl TokenKeyClass {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Virtual => "virtual",
            Self::Disposable => "disposable",
        }
    }
}

// ─── Top-level subcommand enum ───────────────────────────────────────────────

#[derive(Debug, Subcommand)]
pub(crate) enum TokenCommand {
    /// List API tokens.
    List(TokenListArgs),
    /// Get token details by ID.
    Get(TokenGetArgs),
    /// Create a new API token.
    Create(TokenCreateArgs),
    /// Narrow mutable token metadata, bindings, or attached policies.
    Update(TokenUpdateArgs),
    /// Clone a token with a narrower scope.
    Clone(TokenCloneArgs),
    /// Emergency revoke a token and record proof metadata.
    EmergencyRevoke(TokenEmergencyRevokeArgs),
    /// Delete (revoke) a token.
    Delete(TokenDeleteArgs),
    /// Rotate a token, issuing a new key value.
    Rotate(TokenRotateArgs),
    /// Validate a token value against the API.
    Validate(TokenValidateArgs),
    /// Exchange an OAuth authorization code for a one-time-display API token.
    ExchangeCode(super::token_exchange_code::TokenExchangeCodeArgs),
}

// ─── List ────────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub(crate) struct TokenListArgs {
    /// Filter by purpose (general, gateway_runtime, integration).
    #[arg(long)]
    pub(crate) purpose: Option<TokenPurpose>,

    #[arg(long)]
    pub(crate) json: bool,

    /// Show only tokens with derived budget, request, expiry, or terminal alerts.
    #[arg(long)]
    pub(crate) alerts_only: bool,

    #[command(flatten)]
    pub(crate) conn: ConnectArgs,
}
pub(crate) async fn run_list_async(args: TokenListArgs) -> Result<(), CliError> {
    let (_cfg, client) = build_client(&args.conn)?;

    let mut path = "/v1/tokens".to_string();
    let mut params: Vec<String> = Vec::new();
    if let Some(ref purpose) = args.purpose {
        params.push(format!("purpose={}", purpose.as_str()));
    }
    if !params.is_empty() {
        path.push('?');
        path.push_str(&params.join("&"));
    }

    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let mut items = value
        .get("tokens")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if args.alerts_only {
        items.retain(|token| token_alert_state(token) != "ok");
    }

    if items.is_empty() {
        println!("no tokens");
        return Ok(());
    }

    println!(
        "{:<38} {:<20} {:<12} {:<10} {:<16} ALERT",
        "ID", "NAME", "CLASS", "PREFIX", "PURPOSE"
    );
    for t in &items {
        let id = token_identifier(t);
        let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("-");
        let class = t
            .get("actor_class")
            .or_else(|| t.get("key_class"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let prefix = t
            .get("token_prefix")
            .and_then(|v| v.as_str())
            .unwrap_or("…");
        let purpose = t.get("purpose").and_then(|v| v.as_str()).unwrap_or("-");
        let alert = token_alert_state(t);
        println!("{id:<38} {name:<20} {class:<12} {prefix:<10} {purpose:<16} {alert}");
    }

    Ok(())
}

// ─── Get ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub(crate) struct TokenGetArgs {
    /// Token ID to retrieve.
    pub(crate) id: String,

    #[arg(long)]
    pub(crate) json: bool,

    #[command(flatten)]
    pub(crate) conn: ConnectArgs,
}
pub(crate) async fn run_get_async(args: TokenGetArgs) -> Result<(), CliError> {
    let (_cfg, client) = build_client(&args.conn)?;

    let path = format!("/v1/tokens/{}", args.id);
    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let t = value.get("token").unwrap_or(&value);
    println!("id:           {}", token_identifier(t));
    println!(
        "name:         {}",
        t.get("name").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "class:        {}",
        t.get("actor_class")
            .or_else(|| t.get("key_class"))
            .and_then(|v| v.as_str())
            .unwrap_or("-")
    );
    println!(
        "purpose:      {}",
        t.get("purpose").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "token_prefix: {}",
        t.get("token_prefix")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
    );
    println!(
        "created:      {}",
        t.get("created_at").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!("status:       {}", token_status(t));
    println!("alert:        {}", token_alert_state(t));
    if let Some(expires_at) = t.get("expires_at").and_then(|v| v.as_str()) {
        println!("expires_at:   {expires_at}");
    }
    if let Some(depletion) = t.get("depletion") {
        println!(
            "budget:       {} / {} {}",
            format_number(depletion.get("current_spend")),
            format_number(depletion.get("max_budget")),
            depletion
                .get("currency")
                .and_then(|v| v.as_str())
                .unwrap_or("USD")
        );
        println!(
            "requests:     {} / {}",
            format_number(depletion.get("current_requests")),
            format_number(depletion.get("max_requests"))
        );
    }

    Ok(())
}

// ─── Create ──────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub(crate) struct TokenCreateArgs {
    /// Display name for the token.
    #[arg(long)]
    pub(crate) name: String,

    /// Token purpose (general, gateway_runtime, integration).
    #[arg(long, value_enum, default_value = "general")]
    pub(crate) purpose: TokenPurpose,

    /// Governed key class (durable, virtual, disposable).
    #[arg(long, value_enum, default_value = "durable")]
    pub(crate) key_class: TokenKeyClass,

    /// Provider filter (optional).
    #[arg(long)]
    pub(crate) provider: Option<String>,

    /// Model filter. Use more than one time or pass comma-separated values.
    #[arg(long, value_delimiter = ',')]
    pub(crate) model_filter: Vec<String>,

    /// Rate limit — requests for each minute (optional).
    #[arg(long)]
    pub(crate) rate_limit_rpm: Option<u64>,

    /// Rate limit — tokens for each minute (optional).
    #[arg(long)]
    pub(crate) rate_limit_tpm: Option<u64>,

    /// Maximum budget for this token (optional).
    #[arg(long)]
    pub(crate) max_budget: Option<f64>,

    /// Maximum request count for this token (optional).
    #[arg(long)]
    pub(crate) max_requests: Option<u64>,

    /// Budget currency (optional, for example USD).
    #[arg(long)]
    pub(crate) currency: Option<String>,

    /// Bind to a gateway ID (optional).
    #[arg(long)]
    pub(crate) gateway_id: Option<String>,

    /// Bind to a team ID (optional).
    #[arg(long)]
    pub(crate) team_id: Option<String>,

    /// Token expiry duration (for example, 30d or 24h).
    #[arg(long)]
    pub(crate) expires_in: Option<String>,

    #[arg(long)]
    pub(crate) json: bool,

    #[command(flatten)]
    pub(crate) conn: ConnectArgs,
}
pub(crate) async fn run_create_async(args: TokenCreateArgs) -> Result<(), CliError> {
    let (_cfg, client) = build_client(&args.conn)?;

    let mut payload = Map::new();
    payload.insert("name".to_string(), Value::String(args.name));
    payload.insert(
        "purpose".to_string(),
        Value::String(args.purpose.as_str().to_string()),
    );
    payload.insert(
        "key_class".to_string(),
        Value::String(args.key_class.as_str().to_string()),
    );

    let bindings = build_binding_overrides(TokenBindingOverrides {
        provider: args.provider.as_deref(),
        model_filter: &args.model_filter,
        gateway_id: args.gateway_id.as_deref(),
        team_id: args.team_id.as_deref(),
        budget_id: None,
        rate_limit_rpm: args.rate_limit_rpm,
        rate_limit_tpm: args.rate_limit_tpm,
        max_budget: args.max_budget,
        max_requests: args.max_requests,
        currency: args.currency.as_deref(),
    })?;
    if !bindings.is_empty() {
        payload.insert("bindings".to_string(), Value::Object(bindings));
    }
    if let Some(expires_in) = args.expires_in.as_deref() {
        payload.insert(
            "expires_in_seconds".to_string(),
            serde_json::json!(parse_relative_duration_seconds(expires_in)?),
        );
    }

    let value = client
        .post_json_value("/v1/tokens", &Value::Object(payload))
        .await?;

    if args.json {
        return print_json(&value);
    }

    let t = value.get("token").unwrap_or(&value);
    let id = token_identifier(t);
    if let Some(raw_key) = value.get("token_value").and_then(|v| v.as_str()) {
        println!("created token {id}");
        println!("key: {raw_key}  (shown once — save it now)");
    } else {
        println!("created token {id}");
    }
    Ok(())
}

// ─── Update ──────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub(crate) struct TokenUpdateArgs {
    /// Token ID to update.
    pub(crate) id: String,

    /// New display name.
    #[arg(long)]
    pub(crate) name: Option<String>,

    /// Narrow provider binding.
    #[arg(long)]
    pub(crate) provider: Option<String>,

    /// Narrow model filter. Use more than one time or pass comma-separated values.
    #[arg(long, value_delimiter = ',')]
    pub(crate) model_filter: Vec<String>,

    /// Narrow gateway binding.
    #[arg(long)]
    pub(crate) gateway_id: Option<String>,

    /// Narrow team binding.
    #[arg(long)]
    pub(crate) team_id: Option<String>,

    /// Narrow budget binding.
    #[arg(long)]
    pub(crate) budget_id: Option<String>,

    /// Lower requests-per-minute rate limit.
    #[arg(long)]
    pub(crate) rate_limit_rpm: Option<u64>,

    /// Lower tokens-per-minute rate limit.
    #[arg(long)]
    pub(crate) rate_limit_tpm: Option<u64>,

    /// Lower maximum budget.
    #[arg(long)]
    pub(crate) max_budget: Option<f64>,

    /// Lower maximum request count.
    #[arg(long)]
    pub(crate) max_requests: Option<u64>,

    /// Budget currency when max budget is set.
    #[arg(long)]
    pub(crate) currency: Option<String>,

    /// Replace public token metadata with a JSON object.
    #[arg(long)]
    pub(crate) metadata_json: Option<String>,

    /// Replace attached policy IDs. Use more than one time or pass comma-separated values.
    #[arg(long = "policy-id", value_delimiter = ',')]
    pub(crate) policy_ids: Vec<String>,

    #[arg(long)]
    pub(crate) json: bool,

    #[command(flatten)]
    pub(crate) conn: ConnectArgs,
}
pub(crate) async fn run_update_async(args: TokenUpdateArgs) -> Result<(), CliError> {
    let (_cfg, client) = build_client(&args.conn)?;
    let payload = build_update_payload(&args)?;
    let path = format!("/v1/tokens/{}", args.id);
    let value = client.patch_json_value(&path, &payload).await?;

    if args.json {
        return print_json(&value);
    }

    println!("updated token {}", token_identifier(&value));
    println!("status: {}", token_status(&value));
    Ok(())
}

// ─── Clone ───────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub(crate) struct TokenCloneArgs {
    /// Source token ID to clone.
    pub(crate) id: String,

    /// Display name for the clone.
    #[arg(long)]
    pub(crate) name: Option<String>,

    /// Mandatory lifecycle reason for the narrower clone.
    #[arg(long)]
    pub(crate) reason: String,

    /// Narrow provider binding.
    #[arg(long)]
    pub(crate) provider: Option<String>,

    /// Narrow model filter. Use more than one time or pass comma-separated values.
    #[arg(long, value_delimiter = ',')]
    pub(crate) model_filter: Vec<String>,

    /// Narrow gateway binding.
    #[arg(long)]
    pub(crate) gateway_id: Option<String>,

    /// Narrow team binding.
    #[arg(long)]
    pub(crate) team_id: Option<String>,

    /// Narrow budget binding.
    #[arg(long)]
    pub(crate) budget_id: Option<String>,

    /// Lower requests-per-minute rate limit.
    #[arg(long)]
    pub(crate) rate_limit_rpm: Option<u64>,

    /// Lower tokens-per-minute rate limit.
    #[arg(long)]
    pub(crate) rate_limit_tpm: Option<u64>,

    /// Lower maximum budget.
    #[arg(long)]
    pub(crate) max_budget: Option<f64>,

    /// Lower maximum request count.
    #[arg(long)]
    pub(crate) max_requests: Option<u64>,

    /// Budget currency when max budget is set.
    #[arg(long)]
    pub(crate) currency: Option<String>,

    /// Replace public token metadata with a JSON object.
    #[arg(long)]
    pub(crate) metadata_json: Option<String>,

    /// Replace attached policy IDs. Use more than one time or pass comma-separated values.
    #[arg(long = "policy-id", value_delimiter = ',')]
    pub(crate) policy_ids: Vec<String>,

    /// Token expiry duration in seconds.
    #[arg(long)]
    pub(crate) expires_in_seconds: Option<i64>,

    /// Token expiry timestamp accepted by the API.
    #[arg(long)]
    pub(crate) expires_at: Option<String>,

    #[arg(long)]
    pub(crate) json: bool,

    #[command(flatten)]
    pub(crate) conn: ConnectArgs,
}
pub(crate) async fn run_clone_async(args: TokenCloneArgs) -> Result<(), CliError> {
    let (_cfg, client) = build_client(&args.conn)?;
    let payload = build_clone_payload(&args)?;
    let path = format!("/v1/tokens/{}/clone", args.id);
    let value = client.post_json_value(&path, &payload).await?;

    if args.json {
        return print_json(&value);
    }

    let id = token_identifier(&value);
    println!("created narrower token {id}");
    if let Some(raw_key) = value.get("token_value").and_then(|v| v.as_str()) {
        println!("key: {raw_key}  (shown once - save it now)");
    }
    println!(
        "source_token_id: {}",
        value
            .get("source_token_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&args.id)
    );
    println!("status: {}", token_status(&value));
    Ok(())
}

// ─── Emergency revoke ───────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub(crate) struct TokenEmergencyRevokeArgs {
    /// Token ID to emergency revoke.
    pub(crate) id: String,

    /// Mandatory proof reason for emergency revocation.
    #[arg(long)]
    pub(crate) reason: String,

    /// Also revoke active sessions for the token subject when applicable.
    #[arg(long)]
    pub(crate) revoke_active_sessions: bool,

    /// Approve revocation without an interactive prompt.
    #[arg(long)]
    pub(crate) yes: bool,

    #[arg(long)]
    pub(crate) json: bool,

    #[command(flatten)]
    pub(crate) conn: ConnectArgs,
}
pub(crate) async fn run_emergency_revoke_async(
    args: TokenEmergencyRevokeArgs,
) -> Result<(), CliError> {
    if !args.yes {
        return Err(CliError::user(
            "pass --yes to confirm emergency token revocation",
        ));
    }
    let reason = args.reason.trim();
    if reason.is_empty() {
        return Err(CliError::user("emergency revoke requires --reason"));
    }

    let (_cfg, client) = build_client(&args.conn)?;
    let payload = serde_json::json!({
        "reason": reason,
        "revoke_active_sessions": args.revoke_active_sessions,
    });
    let path = format!("/v1/tokens/{}/emergency-revoke", args.id);
    let value = client.post_json_value(&path, &payload).await?;

    if args.json {
        return print_json(&value);
    }

    println!("emergency revoked token {}", token_identifier(&value));
    println!("status: {}", token_status(&value));
    println!(
        "revoked_at: {}",
        value
            .get("revoked_at")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
    );
    println!(
        "revoked_sessions: {}",
        format_number(value.get("revoked_sessions"))
    );
    Ok(())
}

// ─── Delete ──────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub(crate) struct TokenDeleteArgs {
    /// Token ID to revoke.
    pub(crate) id: String,

    /// Approve deletion without an interactive prompt.
    #[arg(long)]
    pub(crate) yes: bool,

    #[arg(long)]
    pub(crate) json: bool,

    #[command(flatten)]
    pub(crate) conn: ConnectArgs,
}
pub(crate) async fn run_delete_async(args: TokenDeleteArgs) -> Result<(), CliError> {
    if !args.yes {
        return Err(CliError::user("pass --yes to confirm token deletion"));
    }

    let (_cfg, client) = build_client(&args.conn)?;

    let path = format!("/v1/tokens/{}", args.id);
    let mut value = client.delete_json_value(&path).await?;
    if let Some(object) = value.as_object_mut() {
        object
            .entry("token_id")
            .or_insert_with(|| Value::String(args.id.clone()));
    }

    if args.json {
        return print_json(&value);
    }

    println!("deleted token {}", args.id);
    Ok(())
}

// ─── Rotate ──────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
pub(crate) struct TokenRotateArgs {
    /// Token ID to rotate.
    pub(crate) id: String,

    #[arg(long)]
    pub(crate) json: bool,

    #[command(flatten)]
    pub(crate) conn: ConnectArgs,
}
pub(crate) async fn run_rotate_async(args: TokenRotateArgs) -> Result<(), CliError> {
    let (_cfg, client) = build_client(&args.conn)?;

    let path = format!("/v1/tokens/{}/rotate", args.id);
    let value = client
        .post_json_value(&path, &serde_json::json!({}))
        .await?;

    if args.json {
        return print_json(&value);
    }

    let t = value.get("token").unwrap_or(&value);
    let new_id = token_identifier(t);
    if let Some(raw_key) = value.get("token_value").and_then(|v| v.as_str()) {
        println!("rotated token {} → new id {new_id}", args.id);
        println!("new key: {raw_key}  (shown once — save it now)");
    } else {
        println!("rotated token {} → new id {new_id}", args.id);
    }
    Ok(())
}

fn token_identifier(value: &Value) -> &str {
    value
        .get("token_id")
        .or_else(|| value.get("id"))
        .or_else(|| value.get("resource_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("-")
}

fn token_status(value: &Value) -> &str {
    value
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
}

fn format_number(value: Option<&Value>) -> String {
    match value {
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Null) | None => "-".to_string(),
        Some(other) => other.to_string(),
    }
}

fn token_alert_state(value: &Value) -> &'static str {
    match token_status(value) {
        "revoked" => return "revoked",
        "expired" => return "expired",
        _ => {}
    }

    if let Some(expires_at) = value.get("expires_at").and_then(|v| v.as_str()) {
        if let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at) {
            let expires_at = expires_at.with_timezone(&chrono::Utc);
            let now = chrono::Utc::now();
            if expires_at <= now {
                return "expired";
            }
            if expires_at - now <= chrono::Duration::days(7) {
                return "expiring_soon";
            }
        }
    }

    let Some(depletion) = value.get("depletion") else {
        return "ok";
    };

    let budget_pct = percent_used(
        depletion.get("current_spend").and_then(Value::as_f64),
        depletion.get("max_budget").and_then(Value::as_f64),
    );
    if let Some(percent) = budget_pct {
        if percent >= 1.0 {
            return "budget_exhausted";
        }
        if percent >= 0.95 {
            return "budget_near_exhausted";
        }
        if percent >= 0.80 {
            return "budget_watch";
        }
    }

    let request_pct = percent_used(
        depletion.get("current_requests").and_then(Value::as_f64),
        depletion.get("max_requests").and_then(Value::as_f64),
    );
    if let Some(percent) = request_pct {
        if percent >= 1.0 {
            return "requests_exhausted";
        }
        if percent >= 0.95 {
            return "requests_near_exhausted";
        }
        if percent >= 0.80 {
            return "requests_watch";
        }
    }

    "ok"
}

fn percent_used(current: Option<f64>, max: Option<f64>) -> Option<f64> {
    let (Some(current), Some(max)) = (current, max) else {
        return None;
    };
    (max > 0.0).then_some(current / max)
}

fn build_update_payload(args: &TokenUpdateArgs) -> Result<Value, CliError> {
    let mut payload = Map::new();
    if let Some(name) = args
        .name
        .as_ref()
        .map(|value| value.trim())
        .filter(|v| !v.is_empty())
    {
        payload.insert("name".to_string(), Value::String(name.to_string()));
    }

    let bindings = build_binding_overrides(TokenBindingOverrides {
        provider: args.provider.as_deref(),
        model_filter: &args.model_filter,
        gateway_id: args.gateway_id.as_deref(),
        team_id: args.team_id.as_deref(),
        budget_id: args.budget_id.as_deref(),
        rate_limit_rpm: args.rate_limit_rpm,
        rate_limit_tpm: args.rate_limit_tpm,
        max_budget: args.max_budget,
        max_requests: args.max_requests,
        currency: args.currency.as_deref(),
    })?;
    if !bindings.is_empty() {
        payload.insert("bindings".to_string(), Value::Object(bindings));
    }

    if let Some(value) = parse_metadata_json(args.metadata_json.as_deref())? {
        payload.insert("metadata".to_string(), value);
    }

    if !args.policy_ids.is_empty() {
        payload.insert("policy_ids".to_string(), policy_ids_value(&args.policy_ids));
    }

    if payload.is_empty() {
        return Err(CliError::user(
            "token update requires at least one mutable field",
        ));
    }

    Ok(Value::Object(payload))
}

fn build_clone_payload(args: &TokenCloneArgs) -> Result<Value, CliError> {
    let reason = args.reason.trim();
    if reason.is_empty() {
        return Err(CliError::user("token clone requires --reason"));
    }

    let mut payload = Map::new();
    payload.insert("reason".to_string(), Value::String(reason.to_string()));
    if let Some(name) = args
        .name
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        payload.insert("name".to_string(), Value::String(name.to_string()));
    }

    let bindings = build_binding_overrides(TokenBindingOverrides {
        provider: args.provider.as_deref(),
        model_filter: &args.model_filter,
        gateway_id: args.gateway_id.as_deref(),
        team_id: args.team_id.as_deref(),
        budget_id: args.budget_id.as_deref(),
        rate_limit_rpm: args.rate_limit_rpm,
        rate_limit_tpm: args.rate_limit_tpm,
        max_budget: args.max_budget,
        max_requests: args.max_requests,
        currency: args.currency.as_deref(),
    })?;
    if !bindings.is_empty() {
        payload.insert("bindings".to_string(), Value::Object(bindings));
    }

    if let Some(value) = parse_metadata_json(args.metadata_json.as_deref())? {
        payload.insert("metadata".to_string(), value);
    }

    if !args.policy_ids.is_empty() {
        payload.insert("policy_ids".to_string(), policy_ids_value(&args.policy_ids));
    }

    if let Some(value) = args.expires_in_seconds {
        payload.insert("expires_in_seconds".to_string(), serde_json::json!(value));
    }
    if let Some(expires_at) = args
        .expires_at
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        payload.insert(
            "expires_at".to_string(),
            Value::String(expires_at.to_string()),
        );
    }

    Ok(Value::Object(payload))
}

struct TokenBindingOverrides<'a> {
    provider: Option<&'a str>,
    model_filter: &'a [String],
    gateway_id: Option<&'a str>,
    team_id: Option<&'a str>,
    budget_id: Option<&'a str>,
    rate_limit_rpm: Option<u64>,
    rate_limit_tpm: Option<u64>,
    max_budget: Option<f64>,
    max_requests: Option<u64>,
    currency: Option<&'a str>,
}

fn build_binding_overrides(
    args: TokenBindingOverrides<'_>,
) -> Result<Map<String, Value>, CliError> {
    let mut bindings = Map::new();
    insert_string_binding(&mut bindings, "provider", args.provider);
    insert_string_binding(&mut bindings, "gateway_id", args.gateway_id);
    insert_string_binding(&mut bindings, "team_id", args.team_id);
    insert_string_binding(&mut bindings, "budget_id", args.budget_id);
    if !args.model_filter.is_empty() {
        let models = args
            .model_filter
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| Value::String(value.to_string()))
            .collect::<Vec<_>>();
        if models.is_empty() {
            return Err(CliError::user("model filter cannot be empty"));
        }
        bindings.insert("model_filter".to_string(), Value::Array(models));
    }
    if let Some(value) = args.rate_limit_rpm {
        bindings.insert("rate_limit_rpm".to_string(), serde_json::json!(value));
    }
    if let Some(value) = args.rate_limit_tpm {
        bindings.insert("rate_limit_tpm".to_string(), serde_json::json!(value));
    }
    if let Some(value) = args.max_budget {
        bindings.insert("max_budget".to_string(), serde_json::json!(value));
    }
    if let Some(value) = args.max_requests {
        bindings.insert("max_requests".to_string(), serde_json::json!(value));
    }
    insert_string_binding(&mut bindings, "currency", args.currency);
    Ok(bindings)
}

fn parse_metadata_json(metadata_json: Option<&str>) -> Result<Option<Value>, CliError> {
    let Some(metadata_json) = metadata_json else {
        return Ok(None);
    };
    let value = serde_json::from_str::<Value>(metadata_json)
        .map_err(|error| CliError::user(format!("invalid --metadata-json: {error}")))?;
    if !value.is_object() {
        return Err(CliError::user("--metadata-json must be a JSON object"));
    }
    Ok(Some(value))
}

fn policy_ids_value(policy_ids: &[String]) -> Value {
    let policies = policy_ids
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| Value::String(value.to_string()))
        .collect::<Vec<_>>();
    Value::Array(policies)
}

fn insert_string_binding(bindings: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        bindings.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn parse_relative_duration_seconds(value: &str) -> Result<i64, CliError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CliError::user("--expires-in cannot be empty"));
    }

    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b's') | Some(b'S') => (&value[..value.len() - 1], 1_i64),
        Some(b'm') | Some(b'M') => (&value[..value.len() - 1], 60_i64),
        Some(b'h') | Some(b'H') => (&value[..value.len() - 1], 60_i64 * 60),
        Some(b'd') | Some(b'D') => (&value[..value.len() - 1], 60_i64 * 60 * 24),
        Some(byte) if byte.is_ascii_digit() => (value, 1_i64),
        _ => {
            return Err(CliError::user(
                "--expires-in must be seconds or use an s, m, h, or d suffix",
            ));
        }
    };

    let amount = number
        .trim()
        .parse::<i64>()
        .map_err(|_| CliError::user("--expires-in must start with a positive integer"))?;
    if amount <= 0 {
        return Err(CliError::user("--expires-in must be greater than zero"));
    }
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| CliError::user("--expires-in is too large"))
}

// ─── Validate ────────────────────────────────────────────────────────────────

#[derive(Debug, Args)]
#[command(
    after_help = "Examples:\n  printf 'vdt_xxx' | verdictan token validate\n  verdictan token validate --force-tty"
)]
pub(crate) struct TokenValidateArgs {
    #[arg(long)]
    pub(crate) json: bool,

    /// Allow token input directly from the terminal as an alternative to a pipe.
    #[arg(long)]
    pub(crate) force_tty: bool,

    #[command(flatten)]
    pub(crate) conn: ConnectArgs,
}
pub(crate) async fn run_validate_async(args: TokenValidateArgs) -> Result<(), CliError> {
    let (_cfg, client) = build_client(&args.conn)?;
    let token_value = read_token_value_from_stdin(args.force_tty)?;

    let payload = serde_json::json!({ "token": token_value });
    let value = client
        .post_json_value("/v1/tokens/validate", &payload)
        .await?;

    if args.json {
        return print_json(&value);
    }

    let valid = value
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if valid {
        let id = value
            .get("token_id")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        println!("valid — token_id: {id}");
    } else {
        let reason = value
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        println!("invalid — {reason}");
    }
    Ok(())
}

fn read_token_value_from_stdin(force_tty: bool) -> Result<String, CliError> {
    if io::stdin().is_terminal() {
        if !force_tty {
            return Err(CliError::user(
                "token validate reads the raw token from stdin; pipe it in or rerun with --force-tty",
            ));
        }
        return read_token_value_from_tty();
    }

    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .map_err(|error| CliError::internal(format!("failed to read stdin: {error}")))?;
    normalize_token_value(buf)
}

fn read_token_value_from_tty() -> Result<String, CliError> {
    eprint!("Token value: ");
    let value = read_secret_value_from_terminal()?;
    eprintln!();
    normalize_token_value(value)
}

fn normalize_token_value(value: String) -> Result<String, CliError> {
    let value = value
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(CliError::user("token value from stdin must not be empty"));
    }
    Ok(value)
}

fn read_secret_value_from_terminal() -> Result<String, CliError> {
    #[cfg(unix)]
    {
        use std::io::BufRead;

        std::process::Command::new("stty")
            .arg("-echo")
            .stdin(std::process::Stdio::inherit())
            .status()
            .map_err(|error| {
                CliError::internal(format!("failed to disable terminal echo: {error}"))
            })?;

        let mut buf = String::new();
        let read_result = io::stdin().lock().read_line(&mut buf);

        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::inherit())
            .status();

        read_result.map_err(|error| {
            CliError::internal(format!("failed to read from terminal: {error}"))
        })?;
        Ok(buf)
    }

    #[cfg(not(unix))]
    {
        use std::io::BufRead;

        let mut buf = String::new();
        io::stdin().lock().read_line(&mut buf).map_err(|error| {
            CliError::internal(format!("failed to read from terminal: {error}"))
        })?;
        Ok(buf)
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
    use chrono::{Duration, Utc};
    use serde_json::json;

    fn update_args() -> TokenUpdateArgs {
        TokenUpdateArgs {
            id: "tok_123".into(),
            name: None,
            provider: None,
            model_filter: Vec::new(),
            gateway_id: None,
            team_id: None,
            budget_id: None,
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            max_requests: None,
            currency: None,
            metadata_json: None,
            policy_ids: Vec::new(),
            json: false,
            conn: ConnectArgs {
                config: None,
                api_url: None,
                profile: "default".into(),
            },
        }
    }

    fn clone_args() -> TokenCloneArgs {
        TokenCloneArgs {
            id: "tok_src".into(),
            name: None,
            reason: "  incident response  ".into(),
            provider: None,
            model_filter: Vec::new(),
            gateway_id: None,
            team_id: None,
            budget_id: None,
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            max_requests: None,
            currency: None,
            metadata_json: None,
            policy_ids: Vec::new(),
            expires_in_seconds: None,
            expires_at: None,
            json: false,
            conn: ConnectArgs {
                config: None,
                api_url: None,
                profile: "default".into(),
            },
        }
    }

    #[test]
    fn command_helper_coverage_token_identifier_and_status_use_fallbacks() {
        assert_eq!(token_identifier(&json!({"token_id": "tok_a"})), "tok_a");
        assert_eq!(token_identifier(&json!({"id": "tok_b"})), "tok_b");
        assert_eq!(token_identifier(&json!({"resource_id": "tok_c"})), "tok_c");
        assert_eq!(token_identifier(&json!({})), "-");

        assert_eq!(token_status(&json!({"status": "active"})), "active");
        assert_eq!(token_status(&json!({})), "unknown");
    }

    #[test]
    fn command_helper_coverage_token_alert_state_handles_expiry_budget_and_request_thresholds() {
        let expired = json!({
            "expires_at": (Utc::now() - Duration::hours(1)).to_rfc3339(),
        });
        assert_eq!(token_alert_state(&expired), "expired");

        let expiring_soon = json!({
            "expires_at": (Utc::now() + Duration::days(2)).to_rfc3339(),
        });
        assert_eq!(token_alert_state(&expiring_soon), "expiring_soon");

        let budget_watch = json!({
            "depletion": {
                "current_spend": 8.5,
                "max_budget": 10.0
            }
        });
        assert_eq!(token_alert_state(&budget_watch), "budget_watch");

        let requests_exhausted = json!({
            "depletion": {
                "current_requests": 100,
                "max_requests": 100
            }
        });
        assert_eq!(token_alert_state(&requests_exhausted), "requests_exhausted");
    }

    #[test]
    fn worker6_token_alert_state_covers_revoked_and_near_exhaustion_thresholds() {
        assert_eq!(token_alert_state(&json!({"status": "revoked"})), "revoked");

        let budget_near_exhausted = json!({
            "depletion": {
                "current_spend": 9.7,
                "max_budget": 10.0
            }
        });
        assert_eq!(
            token_alert_state(&budget_near_exhausted),
            "budget_near_exhausted"
        );

        let requests_near_exhausted = json!({
            "depletion": {
                "current_requests": 97,
                "max_requests": 100
            }
        });
        assert_eq!(
            token_alert_state(&requests_near_exhausted),
            "requests_near_exhausted"
        );

        let requests_watch = json!({
            "depletion": {
                "current_requests": 85,
                "max_requests": 100
            }
        });
        assert_eq!(token_alert_state(&requests_watch), "requests_watch");
    }

    #[test]
    fn command_helper_coverage_format_number_and_percent_used_cover_edge_cases() {
        assert_eq!(format_number(Some(&json!(12))), "12");
        assert_eq!(format_number(Some(&json!("12.5"))), "12.5");
        assert_eq!(format_number(Some(&json!(null))), "-");
        assert_eq!(format_number(Some(&json!({"value": 1}))), "{\"value\":1}");
        assert_eq!(format_number(None), "-");

        assert_eq!(percent_used(Some(8.0), Some(10.0)), Some(0.8));
        assert_eq!(percent_used(Some(8.0), Some(0.0)), None);
        assert_eq!(percent_used(None, Some(10.0)), None);
    }

    #[test]
    fn command_helper_coverage_build_update_payload_trims_and_includes_mutable_fields() {
        let mut args = update_args();
        args.name = Some("  Renamed token  ".into());
        args.provider = Some("  openai  ".into());
        args.model_filter = vec![" gpt-5 ".into(), "  ".into()];
        args.gateway_id = Some(" gw-1 ".into());
        args.team_id = Some(" team-1 ".into());
        args.budget_id = Some(" budget-1 ".into());
        args.rate_limit_rpm = Some(120);
        args.rate_limit_tpm = Some(6000);
        args.max_budget = Some(25.5);
        args.max_requests = Some(400);
        args.currency = Some(" USD ".into());
        args.metadata_json = Some(r#"{"owner":"cli"}"#.into());
        args.policy_ids = vec![" pol-a ".into(), "".into(), "pol-b".into()];

        let payload = build_update_payload(&args).unwrap();
        assert_eq!(payload["name"], "Renamed token");
        assert_eq!(payload["bindings"]["provider"], "openai");
        assert_eq!(payload["bindings"]["gateway_id"], "gw-1");
        assert_eq!(payload["bindings"]["team_id"], "team-1");
        assert_eq!(payload["bindings"]["budget_id"], "budget-1");
        assert_eq!(payload["bindings"]["currency"], "USD");
        assert_eq!(payload["bindings"]["model_filter"], json!(["gpt-5"]));
        assert_eq!(payload["bindings"]["rate_limit_rpm"], 120);
        assert_eq!(payload["bindings"]["rate_limit_tpm"], 6000);
        assert_eq!(payload["bindings"]["max_budget"], 25.5);
        assert_eq!(payload["bindings"]["max_requests"], 400);
        assert_eq!(payload["metadata"]["owner"], "cli");
        assert_eq!(payload["policy_ids"], json!(["pol-a", "pol-b"]));
    }

    #[test]
    fn command_helper_coverage_build_update_payload_rejects_empty_changes() {
        let args = update_args();
        let err = build_update_payload(&args).unwrap_err();
        assert!(err
            .to_string()
            .contains("requires at least one mutable field"));
    }

    #[test]
    fn command_helper_coverage_build_binding_overrides_rejects_blank_model_filter() {
        let err = build_binding_overrides(TokenBindingOverrides {
            provider: None,
            model_filter: &[String::from("   ")],
            gateway_id: None,
            team_id: None,
            budget_id: None,
            rate_limit_rpm: None,
            rate_limit_tpm: None,
            max_budget: None,
            max_requests: None,
            currency: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("model filter cannot be empty"));
    }

    #[test]
    fn command_helper_coverage_build_clone_payload_trims_reason_and_supports_expiry_fields() {
        let mut args = clone_args();
        args.name = Some("  Narrow key  ".into());
        args.provider = Some("openai".into());
        args.expires_in_seconds = Some(3600);
        args.expires_at = Some(" 2026-06-30T00:00:00Z ".into());
        args.metadata_json = Some(r#"{"case":"ir-1"}"#.into());

        let payload = build_clone_payload(&args).unwrap();
        assert_eq!(payload["reason"], "incident response");
        assert_eq!(payload["name"], "Narrow key");
        assert_eq!(payload["bindings"]["provider"], "openai");
        assert_eq!(payload["expires_in_seconds"], 3600);
        assert_eq!(payload["expires_at"], "2026-06-30T00:00:00Z");
        assert_eq!(payload["metadata"]["case"], "ir-1");
    }

    #[test]
    fn command_helper_coverage_build_clone_payload_requires_reason() {
        let mut args = clone_args();
        args.reason = "   ".into();
        let err = build_clone_payload(&args).unwrap_err();
        assert!(err.to_string().contains("requires --reason"));
    }

    #[test]
    fn command_helper_coverage_parse_metadata_json_and_policy_ids_validate_shape() {
        assert!(parse_metadata_json(None).unwrap().is_none());
        assert_eq!(
            parse_metadata_json(Some(r#"{"scope":"org"}"#)).unwrap(),
            Some(json!({"scope":"org"}))
        );
        assert!(parse_metadata_json(Some(r#"["not","an","object"]"#)).is_err());

        assert_eq!(
            policy_ids_value(&[" one ".into(), "".into(), "two".into()]),
            json!(["one", "two"])
        );
    }

    #[test]
    fn worker6_token_parse_metadata_json_rejects_invalid_json() {
        let err = parse_metadata_json(Some("{not-json}")).unwrap_err();
        assert!(err.to_string().contains("invalid --metadata-json"));
    }

    #[test]
    fn command_helper_coverage_insert_string_binding_and_parse_relative_duration_seconds() {
        let mut bindings = Map::new();
        insert_string_binding(&mut bindings, "provider", Some(" openai "));
        insert_string_binding(&mut bindings, "blank", Some("   "));
        assert_eq!(bindings["provider"], "openai");
        assert!(!bindings.contains_key("blank"));

        assert_eq!(parse_relative_duration_seconds("45").unwrap(), 45);
        assert_eq!(parse_relative_duration_seconds("2m").unwrap(), 120);
        assert_eq!(parse_relative_duration_seconds("3H").unwrap(), 10_800);
        assert_eq!(parse_relative_duration_seconds("1d").unwrap(), 86_400);
        assert!(parse_relative_duration_seconds("").is_err());
        assert!(parse_relative_duration_seconds("0").is_err());
        assert!(parse_relative_duration_seconds("ten").is_err());
    }

    #[test]
    fn worker6_token_parse_relative_duration_seconds_rejects_overflow_and_unknown_suffixes() {
        assert!(parse_relative_duration_seconds("1w").is_err());
        assert!(parse_relative_duration_seconds(&format!("{}d", i64::MAX)).is_err());
    }
}
