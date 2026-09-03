# CLI Environment Variables

This file documents the environment variables that the `verdictan` crate reads at
runtime.

Primary readers:

- `src/config/sources.rs`
- `src/gateway/server.rs`
- `src/gateway/cache/semantic.rs`
- `src/commands/gateway_run.rs`
- `src/commands/gateway_install.rs`
- `src/commands/gateway_reload.rs`
- `src/gateway/quality.rs`
- `src/gateway/provider_auth.rs`
- `src/telemetry.rs`

## Host Rust builds

Run Rust commands from this repository root with `make` targets or direct
`cargo`/`nextest`. Optional wrapper: `bash ci/scripts/host-run.sh '<command>'`
when you want the canonical or isolated `target/` layout described below.

- **Canonical artifact directory:** repository-root `target/`.
- **`CARGO_TARGET_DIR`:** overrides the canonical path for one command.
- **`VERDICTAN_ISOLATED_CARGO_TARGET=1`:** uses a gitignored isolated directory
  (`.tmp/cargo-isolated-cli` with an optional suffix).
- Do not run bare `cargo` from a subdirectory without `CARGO_TARGET_DIR`. That
  can write to the wrong `target/` tree.

Common local targets:

```bash
make check
make test-default
make clippy
```

### Runtime payload build inputs

`make runtime-payload` reads build identity values from the environment. The
CLI does not read these values at runtime.

- `SOURCE_SHA` identifies the exact source commit.
- `SOURCE_DATE_EPOCH` sets normalized payload timestamps.
- `BUILD_INPUT_DIGEST` identifies the trusted planner inputs.
- `TOOLCHAIN_ID` identifies the cargo-dist Rust toolchain.
- `BUILDER_ID` identifies the trusted package builder.
- `INVOCATION_ID` identifies the build invocation.

Set `CLI_DIST_BINARY` as a Make variable when cargo-dist uses a nondefault
location. The default is `target/<target>/dist/verdictan`.

### Windows MSVC build requirements

Windows artifacts use `x86_64-pc-windows-msvc`. Cross-compilation from Linux
uses `cargo-xwin`. See `dist-workspace.toml` and
`ci/scripts/install_release_build_deps.sh`. The build requires:

- `cargo-xwin` (installs the Windows MSVC SDK and CRT via `xwin`)
- CMake (for C/C++ dependencies built through `cmake` crates)
- `clang-cl` from the system `clang` package
- `llvm-lib` on `PATH` as the MSVC `lib.exe` replacement
- `lld-link` on `PATH` as the MSVC `link.exe` replacement

`cargo-xwin` supplies only the Windows SDK headers and the CRT libraries. The
build host must supply the LLVM tools. cc-rs calls `clang-cl` for each C
dependency. cc-rs calls `llvm-lib` to build each static library. The Rust link
step calls `lld-link`.

`ci/scripts/install_release_build_deps.sh` keeps these tools available. The
script uses `llvm-lib` and `lld-link` from `PATH` when the host has them. If the
host does not have them, the script adds the `llvm-tools` Rust component. The
script then links the `llvm-ar` and `rust-lld` drivers into
`$CARGO_HOME/dist-msvc-tools/bin` under the two expected program names. Both
drivers select the MSVC behavior from the program name. The script adds that
directory to `PATH` for the later steps of the job.

The Windows release artifact is `verdictan-x86_64-pc-windows-msvc.zip`. That
archive holds `verdictan.exe` and `verdictan-update.exe`. The Linux host builds
both executables and the archive. The release pipeline publishes no Windows MSI
package. Windows users install with the PowerShell installer, with Scoop, or
from the zip archive.

Release builds must not set `AWS_LC_SYS_NO_ASM`.

## Control-Plane Connection

- `VERDICTAN_API_URL` — upstream API base URL.
- `VERDICTAN_API_TOKEN` — preferred API bearer token for CLI control-plane calls.
- `VERDICTAN_CONFIG` — optional path to the CLI YAML config file.

CLI commands no longer accept secret-bearing token flags. Authenticate with
`VERDICTAN_API_TOKEN` or a stored profile from `verdictan auth login`. If
`verdictan token validate` must have a raw token value, pipe the value on stdin. Do not
put the value in argv.

## Gateway Runtime

- `VERDICTAN_API_TOKEN` — unified gateway credential for runtime and control-plane operations.
- `VERDICTAN_RUNTIME_REGISTRATION_ID` — optional connected-gateway runtime identity override. If it is not set, the gateway gets the canonical ID from the machine token.
- `VERDICTAN_GATEWAY_ID` — optional gateway label override. Connected mode uses the control-plane label when available. If it is not available, the runtime generates a 12-character alphanumeric label.
- `VERDICTAN_GATEWAY_MAX_CONCURRENCY` — optional max in-flight upstream requests.
- `VERDICTAN_UPSTREAM_URL` — upstream provider base URL.
- `VERDICTAN_UPSTREAM_API_KEY` — upstream provider secret.
- `VERDICTAN_UPSTREAM_API_KEY_HEADER` — defaults to `Authorization`.
- `VERDICTAN_UPSTREAM_API_KEY_PREFIX` — defaults to `Bearer `.
- `VERDICTAN_AGENT_ID` — optional gateway-bound agent identifier.
- `VERDICTAN_AGENT_NAME` — optional gateway-bound agent name. If `VERDICTAN_AGENT_ID` is not set, `verdictan gateway run` resolves this name before it accepts traffic. It also accepts `VERDICTAN_AGENT_NAME`.

### Client IP and `X-Forwarded-For` (policy, not env)

The gateway does **not** read `VERDICTAN_HTTP_TRUSTED_PROXY_*` or other
client-IP trust env vars. Unlike the API, trusted reverse-proxy membership and
hop walking are policy-config only:

- `ip_allowlist.trusted_proxy_cidrs` — CIDRs authorized to append
  `X-Forwarded-For` for gateway and token IP allowlists
- `ip_rate_limit.trusted_proxy_cidrs` — same semantics for per-IP rate limits

Resolution always starts from the direct peer socket. The gateway ignores a forged
`X-Forwarded-For` from an untrusted peer. When the peer is in a
configured trusted-proxy CIDR, the gateway walks `[X-Forwarded-For..., peer]`
right-to-left. It stops at the first hop that is not in those CIDRs. See
`user-docs/docs/policies/config-security-network.md` and
`user-docs/docs/policies/config-rate-limits.md`.

## Connected Gateway Control Plane

Connected gateway runtime uses `VERDICTAN_API_URL`, `VERDICTAN_API_TOKEN`,
and optional `VERDICTAN_RUNTIME_REGISTRATION_ID` for control-plane calls. It
uses them for config pull, heartbeat, telemetry, access preflight, and session
reporting. The gateway runtime uses its usual HTTP endpoints for chat and model
requests.

Connected-mode chat and model requests fail closed if no deployed linked agent
resolves. `VERDICTAN_AGENT_ID` or `x-verdictan-agent-id` can select an agent by
ID. At startup, `VERDICTAN_AGENT_NAME` can select an agent by name. The gateway
resolves the name before it handles requests. The selected agent must be in the
control-plane gateway-agent lookup for this gateway. If no deployed linked
agent is available, the runtime does not accept provider traffic.

## Connected Gateway Relay

- `VERDICTAN_RELAY_URL` — optional relay broker endpoint override.
- `VERDICTAN_RELAY_TLS_CERT` — optional PEM file path for relay client certificate.
- `VERDICTAN_RELAY_TLS_KEY` — optional PEM file path for relay client private key.
- `VERDICTAN_RELAY_TLS_CA_CERT` — optional PEM file path for relay CA certificate.

Managed public endpoint locality does not come from CLI env vars. The runtime
pulls publication catalog, active revision, and locality metadata from the
control plane. It accepts shared-ingress requests only when:

- the ingress proxy proves the shared relay transport token.
- the ingress proxy proves mutual TLS with the relay verification mark.
- the active gateway publishes the ingress-marked hostname
- the publication state allows public traffic
- the requested region-group commitment matches the active publication revision

Direct gateway requests without the shared-ingress marker use the usual local
listeners. They do not use managed-public-endpoint publication headers.

## Cache And Config Variables

- `VERDICTAN_LLM_CACHE_{BACKEND,TTL_SECS,BUSTER,DIR,MAX_BYTES}` — LLM cache backend, TTL, cache buster, disk path, and max cache size in bytes.
- `VERDICTAN_LLM_CACHE_REDIS_URL` — Redis or Valkey URL for shared cache and distributed rate-limit backends. The URL is mandatory when a shared-state consumer uses a profile other than `local_only`. The policy `distributed_rate_limit.url_env` target can also give the URL. A missing or empty URL stops gateway startup. Runtime loss returns `503 dependency.distributed_state_unavailable`.

## Distributed State Requirement Matrix

At startup, the gateway derives shared-state requirements from deployment inputs
and enabled policy consumers. Backend health does not change the requirement.
See `src/gateway/distributed_state.rs` and `README.md` (Horizontal Scaling).

### Profile inputs

| `connected_mode` | `VERDICTAN_ENV` | `VERDICTAN_DEPLOYMENT_MODE` | Profile |
| --- | --- | --- | --- |
| false | `development` | `self-hosted` / `self_hosted` | `single_node_self_hosted_development` |
| true, or a different env/mode combination | all values | all values | `multi_node_or_connected` |

### Requirement × consumers

If the config enables one or more consumers, shared state is in scope:
`rate_limits`, `budgets`, `fingerprints`, `shared_cache_admission`, and
`replay_protection`.

| Profile | Consumers enabled | Requirement | Backend URL |
| --- | --- | --- | --- |
| all profiles | none | `disabled` | not used |
| `single_node_self_hosted_development` | one or more | `local_only` | optional. The guarantee is process-local. |
| `multi_node_or_connected` | one or more | `required` | mandatory. A missing or empty URL stops startup. |

### Runtime error semantics (`required` only)

| Event | HTTP / probe | Cause / notes |
| --- | --- | --- |
| Missing/empty URL or init failure | Startup fails. The process does not accept traffic. | Only consumers that must have shared state. |
| Runtime backend unavailable | Dependent request **503**. `/readyz` **503**. | `dependency.distributed_state_unavailable`. FailClosed with no local admission. |
| Recovery | Admission resumes after two probes succeed in sequence. | Threshold = `RUNTIME_RECOVERY_SUCCESS_THRESHOLD` (2) |
| Timeouts | Connect 2s / command 2s | Fail closed for `required`. The cause is the same 503 code. |

`local_only` applies only to specified one-node self-hosted development. The
gateway does not select it after a `required` backend failure. Do not identify
a gateway as rollout-grade when the necessary backend is not available.

## Telemetry And Runtime Mode

- `VERDICTAN_OTLP_ENDPOINT` — specified OTLP collector target. It overrides API-derived OTLP routing.
- `VERDICTAN_LOG_FORMAT` — `json` for structured log output. The default is human-readable text.
- `VERDICTAN_ENV` — mandatory runtime and deployment label for telemetry attributes. `development` also enables development-mode cache behavior. If not connected, it is also the only profile that can resolve `local_only`.
- `VERDICTAN_DEPLOYMENT_MODE` — deployment profile label for distributed requirements. Values are `self-hosted`, `connected`, `hosted`, `saas`, `cjis`, `release`, and `production`. A non-`self-hosted` mode with shared-state consumers must have a live Redis or Valkey URL.
- `VERDICTAN_REGION` — region label for multi-region gateway deployments and
  telemetry. It is not used as a CLI region fallback. Configure the CLI region
  explicitly in config or pass `--region`.
- `VERDICTAN_RUNTIME_IMAGE_DIGEST` — optional specified image digest reported in connected-gateway runtime-version heartbeats. Prompt-eval sandbox dispatch uses this to match the gateway against the signed release component record.
- `VERDICTAN_RUNTIME_BUILD_DIGEST` — optional specified build digest reported alongside `VERDICTAN_RUNTIME_IMAGE_DIGEST` for the same fail-closed gateway selection contract.
- `RUST_LOG` — standard Rust log filter.
- `RUST_ENV` — development-mode signal.
- `NODE_ENV` — development-mode signal.

## Gateway Runtime Tuning

- `VERDICTAN_DATA_DIR` — base directory for stored gateway data, such as retry queues.
- `VERDICTAN_HEALTH_PROBE_INTERVAL_SECS` — health probe interval in seconds. The default is `30`.
- `HOSTNAME` — used for gateway fingerprinting and discovery labels.
- `VERDICTAN_CHILD_PROCESS_CAPACITY` — maximum concurrent bounded child processes. The default is `16`. The maximum is `64`.
- `VERDICTAN_CHILD_BLOCKING_CAPACITY` — maximum concurrent blocking child-helper tasks. The default is `4`. The maximum is `16`.
- `VERDICTAN_CHILD_STDOUT_MAX_BYTES` — stdout limit for each child. The default is `8388608` (8 MiB).
- `VERDICTAN_CHILD_STDERR_MAX_BYTES` — stderr limit for each child. The default is `8388608` (8 MiB).
- `VERDICTAN_CHILD_TOTAL_MAX_BYTES` — total stdout and stderr limit for each child. The default is `16777216` (16 MiB). It must be between `max(stdout,stderr)` and `stdout+stderr`.
- `VERDICTAN_CHILD_TIMEOUT_SECONDS` — default child absolute timeout in seconds (default `30`, hard max `300`).

## Gateway Runtime Tuning

- `VERDICTAN_NLI_ENDPOINT` — optional NLI service endpoint used by quality scoring.
- `VERDICTAN_NLI_TOKEN` — optional NLI service token.
- `VERDICTAN_CITATION_URL_LOOKUP` — boolean flag for live citation URL verification.

## Provider-Specific Credentials And Overrides

- Policy config references provider credentials through `secret_key_ref.env` or
  `secret_key_ref.store`. Use Verdictan-prefixed names such as
  `VERDICTAN_OPENAI_API_KEY` or `VERDICTAN_GITHUB_TOKEN`. The CLI does not
  use provider-specific implicit env names. For connected-gateway
  local recovery, the runtime also reads a matching
  Verdictan-prefixed env var such as `VERDICTAN_OPENAI_API_KEY`.
- `VERDICTAN_GITHUB_MODELS_API_VERSION` — GitHub Models API version override.
- `LLAMA_BASE_URL` — local llama.cpp or Ollama endpoint.
- `WATSONX_ACCESS_TOKEN` — IBM WatsonX bearer token override. Specified `watsonx`
  provider routing must have declarative `watsonx_api_version`. It must also
  have one of `watsonx_project_id` or `watsonx_space_id`. The CLI does not derive
  those routing fields from environment variables.
- `GOOGLE_VERTEX_ACCESS_TOKEN` — Vertex AI access token override.
- `GOOGLE_APPLICATION_CREDENTIALS` — path to the GCP service account JSON file.
- `GCE_METADATA_ROOT` — GCE metadata server override.
- `AWS_REGION` and `AWS_DEFAULT_REGION` — ambient AWS SDK region variables for
  code paths that use the AWS SDK default chain. Provider routing and external
  moderation must have specified `aws_region` values in their configuration.
  These env vars do not replace that field. Specified `aws-bedrock` routing must
  also have declarative `bedrock_model_family: anthropic_messages`. An env var
  does not replace that field.
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`

## Supervisor And Service Wrappers

- `VERDICTAN_SUPERVISOR_SERVICE_MODE` — set by `verdictan gateway service` when a supervisor controls the gateway process.

## Signed Updates

- `VERDICTAN_UPDATE_MANIFEST_URL` — selects the signed-manifest update path for
  `verdictan-update`. The updater uses the cargo-dist receipt path when this
  variable is unset.
- `VERDICTAN_UPDATE_PUBLIC_KEY` — base64 Ed25519 public key that verifies the
  selected update manifest.
- `VERDICTAN_UPDATE_ALLOW_DOWNGRADE` — permits an explicitly signed downgrade
  when the value is `1`, `true`, or `yes`. The default rejects downgrades.

## Test Harness

- `VERDICTAN_E2E_BIN` — test-only absolute path to the built CLI executable. The
  package-owned end-to-end harness sets it for process-boundary tests; runtime
  and deployment configuration must not set it.
- `VERDICTAN_E2E_UPDATE_BIN` — test-only absolute path to the built companion
  updater executable.
- `VERDICTAN_TEST_UPDATE_CURRENT_VERSION` and `VERDICTAN_TEST_UPDATE_TARGET` —
  compile-time E2E overrides for update version and target fixtures. Normal
  binaries do not contain these readers.

## Naming Guidance

- Use `VERDICTAN_API_TOKEN` for gateway runtime and control-plane access.
- Use `VERDICTAN_API_TOKEN` only for direct CLI/API auth commands.
- Prefer Verdictan-prefixed provider env names in `secret_key_ref` values. Do
  not use generic ambient names.
