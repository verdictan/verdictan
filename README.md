# Verdictan Gateway CLI

Verdictan is a source-available AI governance gateway. This repository
publishes the `verdictan` binary and the `verdictan` crate.

## License

Verdictan Gateway CLI is **source available** under the Business Source License
1.1 (BUSL-1.1). 
For commercial use outside the Additional Use Grant, contact Verdictan.com

## Install

| Channel | Command |
| --- | --- |
| Homebrew | `brew tap verdictan/verdictan https://github.com/verdictan/verdictan` then `brew install verdictan` |
| Scoop | `scoop bucket add verdictan https://github.com/verdictan/verdictan` then `scoop install verdictan` |
| Shell (Linux/macOS) | `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/verdictan/verdictan/releases/latest/download/verdictan-installer.sh \| sh` |
| PowerShell (Windows) | `irm https://github.com/verdictan/verdictan/releases/latest/download/verdictan-installer.ps1 \| iex` |
| Zip (Windows) | Download `verdictan-x86_64-pc-windows-msvc.zip` from [GitHub Releases](https://github.com/verdictan/verdictan/releases) |
| Debian package (x86_64 Linux) | `sudo dpkg -i verdictan-x86_64-unknown-linux-gnu.deb` after you download the asset from [GitHub Releases](https://github.com/verdictan/verdictan/releases) |
| RPM package (x86_64 Linux) | `sudo rpm -i verdictan-x86_64-unknown-linux-gnu.rpm` after you download the asset from [GitHub Releases](https://github.com/verdictan/verdictan/releases) |
| Container (GHCR) | `docker pull ghcr.io/verdictan/verdictan:latest` |
| Container (Docker Hub) | `docker pull verdictan/verdictan:latest` |
| crates.io | `cargo install verdictan` |

The Debian package and the RPM package install the binary at
`/usr/local/bin/verdictan`. The asset names hold no version number. Read the
release tag on the GitHub Releases page to identify the version. The package
metadata inside each file still holds the exact version.

After install, register a gateway service with `verdictan gateway install`.
Use `verdictan gateway upgrade` for service-managed upgrades. Do not run
`verdictan-update` on Homebrew, Scoop, or container installs; use the package
manager or pull a new image instead.

## Development

Default builds enable all optional features (`distributed`, `otlp`,
`embedding-external`). Use `--no-default-features` when you need a minimal build.

```bash
make check
make test-default
make fmt-check
make clippy
```

See `AGENTS.md` for the full validation matrix and isolated per-feature lanes.

## Runtime payload

Cargo-dist owns each release executable. The container workflow must reuse the
exact Linux executable that cargo-dist produced.

Run `make runtime-payload` after cargo-dist completes. Set the required build
identity variables that the target reports when they are missing.

The target writes `dist-payload/cli/payload-manifest.json`. Run
`make runtime-payload-verify` before image assembly. Set `IMAGE`, and then run
`make runtime-image`. Run `make runtime-image-verify` on a native worker.

## Policy schema

The compile-time policy schema lives at `schema/policy-configuration.schema.json`.
Each release publishes the same file as a release artifact for downstream digest
checks. The runtime payload includes the same source file and records its hash.

## Security

Report vulnerabilities through `SECURITY.md`.

## Contributing

Read `CONTRIBUTING.md` before opening a pull request. Every commit needs a
Developer Certificate of Origin sign-off.

