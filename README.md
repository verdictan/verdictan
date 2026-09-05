# Verdictan

- Website: [https://verdictan.com](https://verdictan.com)
- Documentation: [https://docs.verdictan.com](https://docs.verdictan.com)
- Releases: [GitHub Releases](https://github.com/verdictan/verdictan/releases)
- Package: [crates.io](https://crates.io/crates/verdictan)
- Security: [Security policy](SECURITY.md)

## Overview

Verdictan is a source-available AI governance gateway. It runs between AI
applications and model providers. The gateway applies policy, routes traffic,
protects provider credentials, and records decision evidence.

The key features of Verdictan are:

- **Policy as Config**: Define gateway behavior in YAML. Validate, lint, and
  test policy config before deployment.

- **Governed Model Traffic**: Apply authentication and policy to supported
  model request families. Verdictan supports OpenAI-compatible,
  Anthropic-compatible, WebSocket, and MCP traffic.

- **Provider Routing**: Route requests to configured provider targets. Keep
  provider credentials outside policy YAML.

- **Runtime Controls**: Enforce configured rate limits, budgets, data controls,
  cache rules, and provider access requirements.

- **Decision Evidence**: Record events, History sessions, metrics, and audit
  evidence for governed requests.

For more information, read the
[CLI overview](https://docs.verdictan.com/docs/cli/overview).

## Getting Started & Documentation

Documentation is available on the
[Verdictan documentation site](https://docs.verdictan.com):

- [Install the Gateway](https://docs.verdictan.com/docs/install-gateway)
- [CLI Overview](https://docs.verdictan.com/docs/cli/overview)
- [Config Validation](https://docs.verdictan.com/docs/cli/config-validation)
- [Policy Lifecycle](https://docs.verdictan.com/docs/cli/policy-lifecycle)
- [Gateway Administration](https://docs.verdictan.com/docs/cli/gateway-admin)

## Linux Package Repositories

Install the signing key on Debian or Ubuntu:

```bash
curl -fsSL https://verdictan.github.io/packages/keys/verdictan-packages.asc |
  sudo gpg --dearmor --yes -o /usr/share/keyrings/verdictan-packages.gpg
curl -fsSL https://verdictan.github.io/packages/apt/verdictan.list |
  sudo tee /etc/apt/sources.list.d/verdictan.list >/dev/null
sudo apt update
sudo apt install verdictan
```

Install the repository on CentOS, RHEL, Fedora, or Amazon Linux 2023:

```bash
sudo curl -fsSL https://verdictan.github.io/packages/rpm/verdictan.repo \
  -o /etc/yum.repos.d/verdictan.repo
sudo dnf install verdictan-gateway
```

The current repositories publish packages for x86-64 systems.

## Developing Verdictan

- To compile Verdictan and contribute changes, read
  [CONTRIBUTING.md](CONTRIBUTING.md).
- To review runtime configuration, read
  [ENVIRONMENT.md](ENVIRONMENT.md).
- To report a bug or request a feature, use
  [GitHub Issues](https://github.com/verdictan/verdictan/issues).
- To report an unpatched vulnerability, follow
  [SECURITY.md](SECURITY.md). Do not open a public issue.


## License

[Business Source License 1.1](LICENSE)
