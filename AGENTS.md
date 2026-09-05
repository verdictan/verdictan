# Verdictan CLI Agent Guide

This guide applies to the standalone `verdictan` repository. The crate root is
the repository root. Start with `README.md` for package behavior and
`ENVIRONMENT.md` for the authoritative env inventory.

## Scope

This repository owns the `verdictan` binary and the local or connected gateway
runtime:

- gateway startup, control-plane connectivity, and runtime-side policy
  enforcement
- declarative config authoring, validation, and operator workflows
- control-plane CLI commands for auth, events, history, secrets, and related
  management surfaces
- gateway-side telemetry, caching, provider auth, and runtime integrations

The CLI has two roles: operator tool and data-plane gateway process. Keep the
two roles specified in code and docs.

## Public Repository Content

This repository is public. Apply these rules to comments, documentation,
examples, agent instructions, templates, and generated text:

- Do not add internal operational instructions or infrastructure details.
- Exclude credential identifiers, credential storage locations, private hostnames,
  runner paths, SSH provisioning steps, and internal release or recovery procedures.
- Keep internal runbooks with their owning private repository.
- Keep public installation, configuration, build, and contribution instructions
  that users need. Use generic examples for infrastructure details.
- Preserve required configuration identifiers and executable behavior when you
  remove internal prose.
- Review changed text for internal details before you complete the task.
- Check generated and copied text, including package repository documentation.
  Correct the source and its published copy together.
- Do not repeat removed internal identifiers as examples of prohibited content.

## Read Before Editing

- `README.md`
- `ENVIRONMENT.md`
- the owning command in `src/commands/` or runtime module in `src/gateway/`
- colocated `#[cfg(test)]` modules in `src/**`

If you change the policy schema or user-visible CLI behavior, also coordinate
with `verdictan-docs` for public CLI guides under `docs/cli/` and with
`verdictan-api` for the vendored schema snapshot at
`docs/contracts/policy-configuration.schema.json`.

## ASD-STE100 Documentation

- Write all English technical documentation in ASD-STE100 Issue 9.
- Use active voice. Give one instruction in each sentence.
- Use a maximum of 20 words in procedural sentences and 25 words in descriptive
  sentences.
- Do not use contractions or semicolons in prose. Use American English spelling.
- Use the approved Verdictan termbase in `verdictan-docs` at
  `ASD-STE100-TERMS.md`.
- Do not change code, commands, flags, env vars, paths, identifiers, or output
  that must not change. Rewrite only the prose near these items.

## Core Operating Rules

- Configuration precedence is strict:
  1. CLI flags
  2. environment variables
  3. config file
  4. defaults
- `VERDICTAN_API_TOKEN` is the preferred unified credential for CLI
  control-plane calls and hosted/connected gateway runtime auth.
- Use `VERDICTAN_API_TOKEN` as the supported headless auth path for gateway
  runtime work. Do not invent other machine-auth env names.
- Provider credentials belong in approved secret sources such as `secret_key_ref.env`,
  `secret_key_ref.store`, `--stdin`, or other package-approved secret inputs.
  Do not add plain-text secret flags.
- Prefer Verdictan-prefixed env names for provider secrets. Do not use generic
  ambient names when policy config references env-backed secrets.

## Code Layout

- Put end-user commands in `src/commands/`.
- Put gateway runtime behavior in `src/gateway/`.
- Keep runtime integration helpers near the owning feature. Do not put
  unrelated logic in a monolithic command file.
- Use fixture-backed tests and mock servers when a Rust test seam is available.
  Do not use brittle shell pipelines for this validation.
- Shared test seams live in `src/testing/`. Config fixtures live in `fixtures/`.

## Gateway Runtime Behavior

- The local gateway is the data plane. It enforces policy locally and forwards
  side effects to the API when configured.
- Connected gateway control-plane access uses the same `VERDICTAN_API_URL`,
  `VERDICTAN_API_TOKEN`, and optional `VERDICTAN_RUNTIME_REGISTRATION_ID`
  inputs as other control-plane integration.
- Do not reintroduce removed transport config or env knobs that the runtime no
  longer reads.

## Policy Schema

The compile-time policy schema lives at `schema/policy-configuration.schema.json`.
Each release publishes the same file as a dist extra artifact through
`ci/scripts/stage_policy_schema_artifact.sh`. `verdictan-api` keeps a vendored
copy at `docs/contracts/policy-configuration.schema.json` for API, console,
and release-digest checks. Keep both files identical when you change the
schema.

If you change the policy schema or gateway semantics:

- update the owning `#[cfg(test)]` tests and the fixtures in `fixtures/`,
- update `README.md` when the operator workflow is user-visible,
- coordinate public CLI documentation under `verdictan-docs/docs/cli/`.

## CLI Output And Error Handling

- User-facing commands can write structured output to stdout or stderr.
- Runtime internals and background behavior must use `tracing`. Do not use ad
  hoc debug prints.
- Do not accept secret material from plain flags when the command has an
  approved secret input path.

## Tests And Validation

Use the narrowest owner first. Then, run the applicable package tests.

A change is complete only after you apply it through its owning workflow. You
must also verify the result.

Run Rust commands from the repository root with `make` targets or direct
`cargo`/`nextest`. Optional wrapper: `bash ci/scripts/host-run.sh '<command>'`
when you want the canonical or isolated `target/` layout (see `ENVIRONMENT.md`).

### Test determinism

- Put all CLI verification in colocated `#[cfg(test)]` modules in `src/**`.
  This repository has no `tests/` directory. Do not add Cargo integration
  binaries there.
- Mock servers bind `127.0.0.1:0`. Capture `local_addr()` and inject the
  endpoint into the client that the test checks. Use the helpers in
  `src/testing/`. Do not derive or retry guessed port ranges.
- Mark environment-sensitive tests with `serial_test::serial`. Restore every
  variable that the test changes.
- `src/environment_doc_reconciliation.rs` compares `ENVIRONMENT.md` against the
  env readers in `src/`. Add a new variable to `ENVIRONMENT.md` in the same
  change, or the test fails.
- Do not use wall-clock sleeps or concurrency races as assertions. Use fakes,
  channels, and injected clocks.
- Do not use live provider contracts or upstream API proofs in CI.

### Fast iteration workflow (preferred)

Use the tiered feedback loop below during development. Select the first tier
that gives sufficient feedback. Always prefer a higher tier (lower number) when
it gives sufficient feedback. Do not default to full test suite runs during
active development.

**Tier 1 — Compile check.** Catches syntax, type, and borrow errors without
linking. Use this after each edit:

```bash
make check
```

**Tier 2 — Single test function.** Runs one function. Use this when you iterate
on a selected test:

```bash
cargo nextest run --profile fast -E 'test(=gateway::access_preflight::tests::preflight_returns_ready_byok_on_200)'
```

**Tier 3 — Single test module filter.** Runs every test under one module path.
Use this after you finish work on a selected module:

```bash
cargo nextest run --profile fast -E 'test(/^gateway::access_preflight::/)'
```

**Tier 4 — Additional checks.** Use these commands when the change requires
them:

```bash
make fmt-check
make clippy
make test-default
make test-doc
```

**Tier 5 — Full CI mirror (pre-push):**

```bash
make ci-check
```

`make ci-check` runs the Jenkins validation commands in sequence with the CI
environment (`CARGO_HOME`, `RUSTUP_HOME`, `CARGO_TARGET_DIR`, and
`RUSTFLAGS=-Dwarnings`). Use `make ci-check-fast` to skip the redundant local
`all-features` nextest lane. Neither target runs the Jenkins-only gitleaks scan
or pull-request DCO check.

### Canonical Rust build directories

Run `cargo` from the repository root. The full env-var inventory is in
`ENVIRONMENT.md` — Host Rust builds.

- **Default:** repository-root `target/`.
- **Override:** `CARGO_TARGET_DIR` (special use only).
- **Isolated:** `VERDICTAN_ISOLATED_CARGO_TARGET=1` → `.tmp/cargo-isolated-cli`.
  Optional `VERDICTAN_ISOLATED_CARGO_TARGET_SUFFIX=<name>` for multiple parallel
  isolated compiles. `ci/scripts/host-run.sh` reads both variables.
- Do not set ad-hoc `CARGO_TARGET_DIR` under `.tmp/cargo-task*` or similar.
  Use the official isolated env var or the shared `target/`.
- Remove legacy package-local `target/` trees left by bare `cargo` from the wrong
  working directory.

**Cargo parallelism:** one `cargo` or `nextest` invocation uses parallel
compilation. `ci/scripts/host-run.sh` sets `CARGO_BUILD_JOBS` from `nproc`.
The `fast` profile uses test workers from `test-threads = "num-cpus"`.
Separate simultaneous `cargo` processes contend on the shared `target/` lock.
Prefer one `cargo nextest run` or `make test-default`. Do not run parallel
`make check` shells.

`.config/nextest.toml` defines deterministic local and Jenkins profiles. Each
Jenkins nextest lane writes a distinct JUnit report.

### Nextest timeout semantics

- `slow-timeout = { period, terminate-after }` is the per-test termination
  policy.
- `global-timeout`, when configured, is the whole-run ceiling.
- `leak-timeout` only detects leaked subprocess output pipes after the test
  process exits. It does not detect leaked Tokio tasks.

### Feature-Flag Test Matrix

Default builds enable all optional features (`distributed`, `otlp`,
`embedding-external`). Run each isolated feature lane by itself. This prevents
one feature from masking a different feature or the default build `cfg` paths.
CI runs the default lane plus the isolated per-feature lanes on self-hosted
Linux runners.

| Lane | Command | Purpose |
| --- | --- | --- |
| Default | `make test-default` | `cargo check --tests` and nextest with all optional features |
| Distributed | `make test-distributed` | `distributed` only (`--no-default-features`) |
| OTLP | `make test-otlp` | `otlp` only (`--no-default-features`) |
| External embedding | `make test-embedding-external` | `embedding-external` only (`--no-default-features`) |
| All features | `make test-all-features` | Explicit `--all-features` compatibility check |

Use `make clippy-production` to lint the default lane and the three isolated
feature lanes without `--all-targets`.

### Platform Tests

Tests behind `#[cfg(unix)]` must run on a Unix execution lane:

```bash
make test-unix
```

The `test-unix` target is an alias for `test-default`. Run it on a Linux or
macOS host. A non-Unix build cannot prove Unix-only behavior.

## Release And CI Automation

Cargo updates change `Cargo.lock`. Regenerate `THIRD_PARTY_NOTICES.md` before
you merge the pull request. Run these commands after regeneration:

```bash
bash ci/scripts/regenerate_third_party_notices.sh
make ci-check-deny
make ci-check-third-party
```

`dist-workspace.toml` sets `allow-dirty = ["ci"]`. Do not commit generated CI
files. Jenkins consumes the cargo-dist plan directly.

`dist-workspace.toml` pins `cargo-dist-version = "0.32.0"`. cargo-dist 0.28
rejects `cargo-auditable = true` together with Linux cross-compilation through
cargo-zigbuild. Version 0.32 lifts that restriction and runs
`cargo auditable zigbuild` for cross targets. Keep `cargo-auditable = true` for
all release targets. Do not disable auditable only for `aarch64-unknown-linux-gnu`.

### Extra release artifacts

cargo-dist reads each `[[dist.extra-artifacts]]` `artifacts` entry as a literal
workspace-relative path. Version 0.32.0 expands no glob pattern and no version
template. A path such as `target/debian/*.deb` fails the global build with
`failed to find bin *.deb for extra build`.

Every extra-artifact build script must stage its output under `dist-artifacts/`
with the constant file name that `dist-workspace.toml` declares:

| Script | Staged artifact |
| --- | --- |
| `stage_policy_schema_artifact.sh` | `dist-artifacts/policy-configuration.schema.json` |
| `release_extra_linux_packages.sh` | `dist-artifacts/verdictan-x86_64-unknown-linux-gnu.deb` and `.rpm` |

`release_extra_linux_packages.sh` builds both packages with a GLIBC 2.17
baseline. This baseline supports the listed repository distribution families.
The package tools write version-stamped names by default. The script passes
`--output` with each constant path. The release tag identifies the version.

The `dist-artifacts/` directory is release build output. `.gitignore` covers it
together with `artifacts/`, `dist-manifest.json`, `plan-dist-manifest.json`, and
the CycloneDX `*.cdx.xml` file at the repository root.

## Documentation Sync

Update docs in the same change when user or operator workflows change:

- `README.md` for package-local command behavior
- `ENVIRONMENT.md` for every env var that a reader in `src/` adds or removes
- `CONTRIBUTING.md` for contribution terms, DCO sign-off, and license policy
- `docs/license-faq.md` for public BUSL-1.1 interpretive guidance
- Public CLI workflows in `verdictan-docs/docs/cli/` when behavior is
  customer-visible

Do not change the console handoff boundary. The console can guide users into
CLI workflows. Local editing, validation, and gateway startup occur in the
terminal with `verdictan`.

## Repository Layout (quick reference)

| Path | Role |
| --- | --- |
| `src/` | CLI and gateway source, with colocated `#[cfg(test)]` tests |
| `src/commands/` | End-user CLI commands |
| `src/gateway/` | Gateway runtime behavior |
| `src/testing/` | Shared deterministic test helpers and mock servers |
| `fixtures/` | Declarative config, policy config, and workflow test fixtures |
| `schema/` | Policy configuration JSON schema (source of truth) |
| `Makefile` | Primary local validation entry points |
| `.config/nextest.toml` | Local and Jenkins nextest profiles |
| `ci/scripts/` | Release pipeline, distrib local-cache helper (`release_distrib_cache.sh`), SPDX and third-party notice checks, and optional dev host-run wrapper |
| `Jenkinsfile` | Branch, pull-request, and tag pipeline entry point |
| `.github/` | GitHub issue and pull-request templates, plus Cargo Dependabot |
| `docs/license-faq.md` | Public BUSL-1.1 interpretive guidance |
| `verdictan.json` | In-repo Scoop manifest (bucket source) |
