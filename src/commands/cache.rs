// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::{Args, Subcommand};

use crate::error::CliError;
use crate::gateway::cache::ProviderResponseCache;

const CACHE_TABLE_KEY_DISPLAY_WIDTH: usize = 50;
const CACHE_TABLE_KEY_MAX_CHARS: usize = 48;
const CACHE_TABLE_KEY_TRUNCATED_CHARS: usize = 47;

#[derive(Debug, Args)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub command: CacheCommand,
}

#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    /// Display cache statistics: backend type, entry count, total size, hit/miss ratio.
    Stats,
    /// Clear all cache entries from the local filesystem cache.
    Clear(CacheClearArgs),
    /// Show metadata for a specified cache entry by key.
    Inspect(CacheInspectArgs),
    /// List the largest or most recently accessed cache entries.
    List(CacheListArgs),
}

#[derive(Debug, Args)]
pub struct CacheClearArgs {
    /// Skip confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct CacheInspectArgs {
    /// Cache key to examine.
    pub key: String,
}

#[derive(Debug, Args)]
pub struct CacheListArgs {
    /// Number of entries to display.
    #[arg(long, default_value = "20")]
    pub top: usize,

    /// Sort by size (largest first). Default sorts by most recently accessed.
    #[arg(long)]
    pub by_size: bool,
}

pub fn run(args: CacheArgs) -> Result<(), CliError> {
    match args.command {
        CacheCommand::Stats => run_stats(),
        CacheCommand::Clear(clear_args) => run_clear(clear_args),
        CacheCommand::Inspect(inspect_args) => run_inspect(inspect_args),
        CacheCommand::List(list_args) => run_list(list_args),
    }
}

fn block_on_cache<T>(work: impl std::future::Future<Output = T>) -> Result<T, CliError> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CliError::internal(format!("failed to start cache command runtime: {error}"))
        })?
        .block_on(work))
}

fn cache_from_env() -> Result<ProviderResponseCache, CliError> {
    block_on_cache(ProviderResponseCache::from_env())?
}

fn run_stats() -> Result<(), CliError> {
    let cache = cache_from_env()?;
    let config = cache.config();

    println!("Cache Backend: {}", config.backend.as_str());
    println!("Enabled:       {}", config.enabled);

    if let Some(dir) = cache.cache_directory() {
        println!("Directory:     {}", dir.display());
    }

    if let Some(stats) = cache.filesystem_stats() {
        let total_mb = stats.total_size_bytes as f64 / (1024.0 * 1024.0);
        let max_mb = stats.max_bytes as f64 / (1024.0 * 1024.0);
        let total_lookups = stats.hit_count + stats.miss_count;
        let hit_ratio = if total_lookups > 0 {
            (stats.hit_count as f64 / total_lookups as f64) * 100.0
        } else {
            0.0
        };

        println!("Entry Count:   {}", stats.entry_count);
        println!("Total Size:    {total_mb:.1} MB / {max_mb:.0} MB");
        println!(
            "Hit/Miss:      {} / {} ({hit_ratio:.1}% hit rate)",
            stats.hit_count, stats.miss_count
        );
        println!("Evictions:     {}", stats.eviction_count);
        println!("Warmed:        {}", stats.warmed);
    } else {
        println!("(filesystem stats not available for this backend)");
    }

    Ok(())
}

fn run_clear(args: CacheClearArgs) -> Result<(), CliError> {
    if !args.yes {
        eprint!("This will delete all cached entries. Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| CliError::internal(format!("failed to read stdin: {e}")))?;
        if !matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let cache = cache_from_env()?;
    block_on_cache(cache.clear())?;
    println!("Cache cleared.");
    Ok(())
}

fn run_inspect(args: CacheInspectArgs) -> Result<(), CliError> {
    let cache = cache_from_env()?;
    let entry = block_on_cache(cache.raw_entry_for_test(&args.key))?;

    match entry {
        Some(stored) => {
            let body_bytes = base64::engine::general_purpose::STANDARD
                .decode(&stored.body_base64)
                .unwrap_or_default();
            let age_secs = crate::gateway::cache::current_unix_secs()
                .saturating_sub(stored.stored_at_unix_secs);

            println!("Key:            {}", args.key);
            println!("Status:         {}", stored.status);
            println!("Body Size:      {} bytes", body_bytes.len());
            println!(
                "Stored At:      {} ({}s ago)",
                stored.stored_at_unix_secs, age_secs
            );
            println!("Key Version:    {}", stored.key_version);
            println!("Headers:        {} entries", stored.headers.len());

            let content_type = stored
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-type"))
                .map(|h| {
                    base64::engine::general_purpose::STANDARD
                        .decode(&h.value_base64)
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok())
                        .unwrap_or_else(|| "(binary)".to_string())
                });
            if let Some(ct) = content_type {
                println!("Content-Type:   {ct}");
            }
        }
        None => {
            println!("No cache entry found for key: {}", args.key);
        }
    }

    Ok(())
}

fn run_list(args: CacheListArgs) -> Result<(), CliError> {
    let cache = cache_from_env()?;
    let entries = cache.list_top_entries(args.top, args.by_size);

    if entries.is_empty() {
        println!("Cache is empty.");
        return Ok(());
    }

    let sort_label = if args.by_size {
        "size (largest first)"
    } else {
        "access time (most recent first)"
    };
    println!("Top {} entries by {sort_label}:\n", entries.len());
    println!(
        "{:<CACHE_TABLE_KEY_DISPLAY_WIDTH$} {:>10} {:>12}",
        "KEY", "SIZE", "ACCESSED AGO"
    );
    println!("{}", "-".repeat(74));

    for (key, size, accessed_ago_secs) in &entries {
        let display_key = format_table_key(key);
        let size_str = format_bytes(*size);
        let ago_str = format_duration(*accessed_ago_secs);
        println!(
            "{:<CACHE_TABLE_KEY_DISPLAY_WIDTH$} {:>10} {:>12}",
            display_key, size_str, ago_str
        );
    }

    Ok(())
}

fn format_table_key(key: &str) -> String {
    if key.chars().count() > CACHE_TABLE_KEY_MAX_CHARS {
        let mut truncated = key
            .chars()
            .take(CACHE_TABLE_KEY_TRUNCATED_CHARS)
            .collect::<String>();
        truncated.push('…');
        truncated
    } else {
        key.to_string()
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d ago", secs / 86400)
    } else if secs >= 3600 {
        format!("{}h ago", secs / 3600)
    } else if secs >= 60 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{secs}s ago")
    }
}

use base64::Engine as _;

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
    fn command_helper_coverage_format_bytes_uses_human_units() {
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(3 * 1_048_576), "3.0 MB");
    }

    #[test]
    fn command_helper_coverage_format_duration_uses_expected_buckets() {
        assert_eq!(format_duration(45), "45s ago");
        assert_eq!(format_duration(120), "2m ago");
        assert_eq!(format_duration(7_200), "2h ago");
        assert_eq!(format_duration(172_800), "2d ago");
    }

    #[test]
    fn format_bytes_exact_boundaries() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1_048_575), "1024.0 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
    }

    #[test]
    fn format_duration_exact_boundaries() {
        assert_eq!(format_duration(0), "0s ago");
        assert_eq!(format_duration(59), "59s ago");
        assert_eq!(format_duration(60), "1m ago");
        assert_eq!(format_duration(3599), "59m ago");
        assert_eq!(format_duration(3600), "1h ago");
        assert_eq!(format_duration(86399), "23h ago");
        assert_eq!(format_duration(86400), "1d ago");
    }

    #[test]
    fn cache_command_variants_debug() {
        let stats = CacheCommand::Stats;
        let clear = CacheCommand::Clear(CacheClearArgs { yes: true });
        let inspect = CacheCommand::Inspect(CacheInspectArgs {
            key: "k".to_string(),
        });
        let list = CacheCommand::List(CacheListArgs {
            top: 10,
            by_size: false,
        });
        assert!(format!("{:?}", stats).contains("Stats"));
        assert!(format!("{:?}", clear).contains("Clear"));
        assert!(format!("{:?}", inspect).contains("Inspect"));
        assert!(format!("{:?}", list).contains("List"));
    }

    #[test]
    fn cache_args_debug() {
        let args = CacheArgs {
            command: CacheCommand::Stats,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("CacheArgs"));
        assert!(debug.contains("Stats"));
    }

    #[test]
    fn cache_clear_args_yes_false() {
        let args = CacheClearArgs { yes: false };
        let debug = format!("{:?}", args);
        assert!(debug.contains("false"));
    }

    #[test]
    fn cache_list_args_by_size_true() {
        let args = CacheListArgs {
            top: 50,
            by_size: true,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("50"));
        assert!(debug.contains("true"));
    }

    #[test]
    fn cache_inspect_args_key_preserved() {
        let args = CacheInspectArgs {
            key: "abc123".to_string(),
        };
        assert_eq!(args.key, "abc123");
    }

    #[test]
    fn format_bytes_large_values() {
        assert_eq!(format_bytes(10_485_760), "10.0 MB");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(512), "512 B");
    }

    #[test]
    fn format_duration_large_values() {
        assert_eq!(format_duration(172800), "2d ago");
        assert_eq!(format_duration(7200), "2h ago");
        assert_eq!(format_duration(300), "5m ago");
        assert_eq!(format_duration(1), "1s ago");
    }

    #[test]
    fn format_table_key_preserves_short_ascii_keys() {
        assert_eq!(format_table_key("tenant:small"), "tenant:small");
    }

    #[test]
    fn format_table_key_truncates_at_char_boundaries() {
        let key = format!("{}🙂suffix", "a".repeat(47));
        let expected = format!("{}…", "a".repeat(47));
        assert_eq!(format_table_key(&key), expected);
    }
}
