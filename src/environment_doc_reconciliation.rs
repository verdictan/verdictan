// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Reconciles `ENVIRONMENT.md` with environment variable readers in `src/`.

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const ENVIRONMENT_MD: &str = include_str!("../ENVIRONMENT.md");

    /// Documented names that resolve dynamically and are not literal `env::var` targets.
    const DOCUMENTED_DYNAMIC_ALLOWLIST: &[&str] = &["VERDICTAN_GITHUB_TOKEN"];

    /// Documented prefix groups. The file uses brace expansion, not one variable each.
    const DOCUMENTED_PREFIX_ALLOWLIST: &[&str] =
        &["VERDICTAN_LLM_CACHE_", "VERDICTAN_HTTP_TRUSTED_PROXY_"];

    /// Documented host-build and release-pipeline variables that the runtime crate does not read.
    const DOCUMENTED_BUILD_ONLY_ALLOWLIST: &[&str] = &[
        "CARGO_TARGET_DIR",
        "VERDICTAN_DISTRIB_REMOTE_HOST",
        "VERDICTAN_DISTRIB_REMOTE_ROOT",
        "VERDICTAN_ISOLATED_CARGO_TARGET",
    ];

    /// Documented ambient variables consumed by dependencies, not direct `env::var` readers.
    const DOCUMENTED_AMBIENT_ALLOWLIST: &[&str] = &[
        "AWS_DEFAULT_REGION",
        "AWS_REGION",
        "NODE_ENV",
        "RUST_ENV",
        "RUST_LOG",
    ];

    /// Readers that are test-only, ambient, or otherwise intentionally omitted from ENVIRONMENT.md.
    const READER_EXEMPT_ALLOWLIST: &[&str] = &[
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "CARGO_MANIFEST_DIR",
        "GCE_METADATA_ROOT",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_VERTEX_ACCESS_TOKEN",
        "HOME",
        "HOSTNAME",
        "LLAMA_BASE_URL",
        "PATH",
        "REDIS_URL",
        "VERDICTAN_ADVERTISE_ADDRESS",
        "VERDICTAN_EVENT_WAL_MAX_BYTES",
        "VERDICTAN_HTTP_TRUSTED_PROXY_CIDRS",
        "VERDICTAN_HTTP_TRUSTED_PROXY_DEPTH",
        "VERDICTAN_LANG",
        "VERDICTAN_LIB_TEST_VAR",
        "VERDICTAN_MCP_OUTBOX_SLOT",
        "VERDICTAN_READ_MODEL_STALE_AFTER_SECS",
        "VERDICTAN_RELAY_ENDPOINT",
        "VERDICTAN_RUNTIME_ACTIVE_BINARY_PATH",
        "VERDICTAN_RUNTIME_LAST_RESTART_AT",
        "VERDICTAN_RUNTIME_SERVICE_MANAGER",
        "VERDICTAN_RUNTIME_TARGET_BINARY_PATH",
        "VERDICTAN_RUNTIME_TARGET_VERSION",
        "VERDICTAN_RUNTIME_UPGRADE_PHASE",
        "VERDICTAN_SERVICE_ENV_BLOCK",
        "VERDICTAN_SERVICE_REGISTRY_NAME",
        "VERDICTAN_TEST_GATEWAY_START_RUNTIME_RESULT",
        "VERDICTAN_TEST_HOME",
        "VERDICTAN_TEST_SERVICE_COMMAND_LOG",
        "VERDICTAN_TEST_SERVICE_PLATFORM",
        "VERDICTAN_TEST_WATSONX_IAM_URL",
        "WATSONX_ACCESS_TOKEN",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
    ];

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
    }

    fn is_env_var_name(name: &str) -> bool {
        let Some(first) = name.chars().next() else {
            return false;
        };
        first.is_ascii_uppercase()
            && name
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    }

    fn expand_brace_group(token: &str) -> Vec<String> {
        let Some((prefix, rest)) = token.split_once('{') else {
            return vec![token.to_string()];
        };
        let Some((options, suffix)) = rest.split_once('}') else {
            return vec![token.to_string()];
        };
        options
            .split(',')
            .map(|option| format!("{prefix}{option}{suffix}"))
            .collect()
    }

    fn documented_variables() -> BTreeSet<String> {
        let mut documented = BTreeSet::new();
        for line in ENVIRONMENT_MD.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("- `") {
                continue;
            }
            let after = &trimmed[3..];
            let Some(end) = after.find('`') else {
                continue;
            };
            let token = &after[..end];
            if token.contains('.') || token.contains('/') || token.contains('=') {
                continue;
            }
            for name in expand_brace_group(token) {
                if is_env_var_name(&name) {
                    documented.insert(name);
                }
            }
        }
        documented
    }

    fn is_documented_allowlisted(name: &str) -> bool {
        if DOCUMENTED_DYNAMIC_ALLOWLIST.contains(&name)
            || DOCUMENTED_BUILD_ONLY_ALLOWLIST.contains(&name)
            || DOCUMENTED_AMBIENT_ALLOWLIST.contains(&name)
            || name.starts_with("VERDICTAN_CHILD_")
        {
            return true;
        }
        DOCUMENTED_PREFIX_ALLOWLIST
            .iter()
            .any(|prefix| name.starts_with(prefix))
    }

    fn is_reader_exempt(name: &str) -> bool {
        READER_EXEMPT_ALLOWLIST.contains(&name)
            || name.starts_with("VERDICTAN_TEST_")
            || name.starts_with("VERDICTAN_CHILD_")
            || name.starts_with("VERDICTAN_CALLBACK_")
            || name == "UID"
            || name == "VERDICTAN_NONEXISTENT_TEST_VAR_12345"
    }

    fn collect_string_literals(line: &str, readers: &mut BTreeSet<String>) {
        let mut search = line;
        while let Some(start) = search.find('"') {
            let after = &search[start + 1..];
            let Some(end) = after.find('"') else {
                break;
            };
            let name = &after[..end];
            if is_env_var_name(name) {
                readers.insert(name.to_string());
            }
            search = &after[end + 1..];
        }
    }

    fn collect_source_readers(src_root: &Path) -> BTreeSet<String> {
        let mut readers = BTreeSet::new();
        let env_markers = [
            "std::env::var(",
            "std::env::var_os(",
            "parse_env_bounded(",
            "optional_env(",
            "read_env(",
            "set_var(",
            "remove_var(",
            "unset_var(",
        ];
        let mut stack = vec![src_root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).expect("read src directory") {
                let entry = entry.expect("dir entry");
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                let content = fs::read_to_string(&path).expect("read source file");
                for line in content.lines() {
                    if env_markers.iter().any(|marker| line.contains(marker))
                        || line.contains("\"VERDICTAN_CHILD_")
                    {
                        collect_string_literals(line, &mut readers);
                    }
                }
            }
        }
        readers
    }

    #[test]
    fn environment_md_matches_env_var_readers() {
        let documented = documented_variables();
        let readers = collect_source_readers(&repo_root().join("src"));

        let undocumented_readers: Vec<_> = readers
            .iter()
            .filter(|name| !documented.contains(*name))
            .filter(|name| !is_reader_exempt(name))
            .cloned()
            .collect();
        assert!(
            undocumented_readers.is_empty(),
            "env readers missing from ENVIRONMENT.md: {undocumented_readers:?}"
        );

        let stale_docs: Vec<_> = documented
            .iter()
            .filter(|name| !readers.contains(*name))
            .filter(|name| !is_documented_allowlisted(name))
            .cloned()
            .collect();
        assert!(
            stale_docs.is_empty(),
            "ENVIRONMENT.md documents variables with no reader in src/: {stale_docs:?}"
        );
    }

    #[test]
    fn documented_dynamic_and_prefix_allowlists_are_recorded() {
        let documented = documented_variables();
        let readers = collect_source_readers(&repo_root().join("src"));

        assert!(ENVIRONMENT_MD.contains("VERDICTAN_GITHUB_TOKEN"));
        assert!(!readers.contains("VERDICTAN_GITHUB_TOKEN"));

        for suffix in ["BACKEND", "TTL_SECS", "BUSTER", "DIR", "MAX_BYTES"] {
            let name = format!("VERDICTAN_LLM_CACHE_{suffix}");
            assert!(documented.contains(&name), "missing documented {name}");
            assert!(readers.contains(&name), "missing reader for {name}");
        }

        for name in [
            "VERDICTAN_HTTP_TRUSTED_PROXY_DEPTH",
            "VERDICTAN_HTTP_TRUSTED_PROXY_CIDRS",
        ] {
            assert!(
                !documented.contains(name),
                "{name} must not be documented as a gateway reader"
            );
        }
    }
}
