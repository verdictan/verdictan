# License FAQ

This page explains the Business Source License 1.1 (BUSL-1.1) for the
`verdictan` repository. The full license text is in `LICENSE`. This page is
interpretive guidance only. The `LICENSE` file controls if the two texts
conflict.

## Is this project open source?

No. BUSL-1.1 is a **source-available** license. It is not an open-source
license under OSI, FSF, or Debian definitions. Each released version converts
to Apache-2.0 on its Change Date.

## What can one legal entity do in production?

The Additional Use Grant permits production use within **one legal entity** for
that entity's internal business purposes. Employees, officers, directors, and
individual contractors of that entity may operate the Licensed Work for that
entity.

## Can a corporate group share one production deployment?

No. Each legal entity in a corporate group is a third party under the grant.
Each entity that runs production use needs its own permitted use under the
grant, or its own commercial license from Verdictan.com

## Can a managed service provider run this for customers?

No. You may not offer the Licensed Work to a third party as a hosted or managed
service. This rule applies whether or not you charge a fee. A contractor may
operate the gateway for one permitted entity. A contractor may not use one
entity's permitted use to serve other entities.

## Can a consultant or systems integrator operate the gateway for a customer?

Yes, when the customer is one permitted legal entity and the consultant acts only
for that entity. The consultant may install, configure, and operate the Licensed
Work in the customer's production environment under that entity's permitted use.

The consultant may not use one customer's permitted use to serve other customers.
The consultant may not host or operate a shared instance that multiple customers
use. Each customer that runs production use needs its own permitted use under
the grant, or its own commercial license from Verdictan.com

## Can I fork this repository or distribute modified source?

You may copy, modify, and redistribute the source for non-production use under
BUSL-1.1 without restriction.

For production use, the Additional Use Grant applies to your fork or derivative
the same way it applies to the upstream Licensed Work. You may not use a fork to
offer the Licensed Work to third parties as a hosted or managed service.

All copies and derivative works of the Licensed Work remain under BUSL-1.1 with
the same parameters until the Change Date for that version. On the Change Date,
that version converts to Apache-2.0. If you mix BUSL-1.1 source with code under
another license, both licenses may apply to the combined work. Read the `LICENSE`
file and get legal advice before you publish a mixed fork.

## Can we use the gateway behind our own product?

Yes, when your customers do not receive access to the Licensed Work itself.
Internal production use that supports your products is permitted when customers
do not use the gateway endpoints, proxy, admin UI, MCP interface, or CLI that
you operate for them.

## What happens on the Change Date?

Each released version carries its own Change Date in `LICENSE`. On that date,
that version becomes available under Apache-2.0. Earlier and later versions keep
their own dates. BUSL-1.1 applies separately to each version.

## Why does `LICENSE` on `main` contain placeholders?

Development branches may show `<<VERSION>>` and `<<CHANGE-DATE>>` tokens. The
release pipeline stamps `LICENSE` from `LICENSE.template` for each release tag.
Shipped binaries, archives, and container images carry the stamped file.

## How do I get a commercial license?

Contact Verdictan.com at [engineering@verdictan.com](mailto:engineering@verdictan.com)
when you need production use outside the Additional Use Grant. Open a GitHub
issue in this repository and describe your use case if you need routing help.

## How do contributions get licensed?

Read `CONTRIBUTING.md`. Every contribution uses inbound-equals-outbound terms
under BUSL-1.1 and converts with the project on each version's Change Date.

## Where are third-party licenses listed?

See `THIRD_PARTY_NOTICES.md`. Release tarballs, Windows zip archives, Debian
packages, RPM packages, and container images include that file. Regenerate it after
`Cargo.lock` changes with:

```bash
bash ci/scripts/regenerate_third_party_notices.sh
```

CI fails when the file is stale relative to `Cargo.lock`.

## References

- `LICENSE` and `LICENSE.template`
- `CONTRIBUTING.md`
- [Business Source License 1.1](https://mariadb.com/bsl11/)
