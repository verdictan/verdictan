# Changelog

All notable changes to this project are documented in this file.

## Unreleased

- Add automated, strictly confined Snap Store packaging and publication for
  AMD64 and ARM64.
- Add a signed x86-64 Flatpak bundle to each GitHub release.
- Add deterministic WinGet manifests and community repository submission.
- Add signed APT and RPM repositories for supported Linux distributions.

## 0.1.1 (2026-09-04)

First complete public release of the Verdictan gateway CLI.

Verdictan is a source-available AI governance gateway. It enforces policy
locally, audits LLM traffic, and connects to the Verdictan control plane when
configured.

This release ships the `verdictan` binary for Linux, macOS, and Windows. It
includes shell and PowerShell installers, a Homebrew formula, Debian and RPM
packages, and the policy configuration JSON schema.

Documentation: https://docs.verdictan.com

### License

Verdictan Gateway CLI is source available under the Business Source License 1.1
(BUSL-1.1). See [docs/license-faq.md](docs/license-faq.md) for license guidance.

## 0.1.0 (2026-08-27)

Withdrawn before a complete public release. The crates.io package is yanked.
