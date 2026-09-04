# Verdictan

- Website: [https://verdictan.com](https://verdictan.com)
- Documentation: [https://docs.verdictan.com](https://docs.verdictan.com)
- Releases: [GitHub Releases]([https://github.com/verdictan/verdictan/releases](https://github.com/verdictan/verdictan/releases))
- Package: [crates.io]([https://crates.io/crates/verdictan](https://crates.io/crates/verdictan))
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
[CLI overview]([https://docs.verdictan.com/docs/cli/overview](https://docs.verdictan.com/docs/cli/overview)).

## Getting Started & Documentation

Documentation is available on the
[Verdictan documentation site]([https://docs.verdictan.com](https://docs.verdictan.com)):

- [Install the Gateway]([https://docs.verdictan.com/docs/install-gateway](https://docs.verdictan.com/docs/install-gateway))
- [CLI Overview]([https://docs.verdictan.com/docs/cli/overview](https://docs.verdictan.com/docs/cli/overview))
- [Config Validation]([https://docs.verdictan.com/docs/cli/config-validation](https://docs.verdictan.com/docs/cli/config-validation))
- [Policy Lifecycle]([https://docs.verdictan.com/docs/cli/policy-lifecycle](https://docs.verdictan.com/docs/cli/policy-lifecycle))
- [Gateway Administration]([https://docs.verdictan.com/docs/cli/gateway-admin](https://docs.verdictan.com/docs/cli/gateway-admin))


## Developing Verdictan

- To compile Verdictan and contribute changes, read
  [CONTRIBUTING.md](CONTRIBUTING.md).
- To review runtime configuration, read
  [ENVIRONMENT.md](ENVIRONMENT.md).
- To report a bug or request a feature, use
  [GitHub Issues]([https://github.com/verdictan/verdictan/issues](https://github.com/verdictan/verdictan/issues)).
- To report an unpatched vulnerability, follow
  [SECURITY.md](SECURITY.md). Do not open a public issue.


## License

[Business Source License 1.1](LICENSE)
