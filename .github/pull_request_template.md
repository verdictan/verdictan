## Summary

<!-- What does this pull request change and why? -->

## Test plan

<!-- List the commands you ran and the results you observed. -->

- [ ] I ran the validation commands below or narrower lanes that match this change.

### Validation commands

Use the narrowest lane that gives sufficient feedback. Run from the repository root.

| Scope | Command |
| --- | --- |
| Compile check | `make check` |
| Format | `make fmt-check` |
| Lint | `make clippy` |
| Default tests | `make test-default` |
| Doc tests | `make test-doc` |
| Full CI mirror | `make ci-check` |
| Faster CI mirror | `make ci-check-fast` |

When you change only one area, use a narrower lane:

| Change | Command |
| --- | --- |
| `Cargo.toml` or `Cargo.lock` | `make ci-check-deny` and `make ci-check-third-party` |
| `src/**` | `make ci-check-spdx` |
| One test function | `cargo nextest run --profile fast -E 'test(=my_test_fn)'` |
| Policy schema | Validate config and sync `schema/policy-configuration.schema.json` with the platform repository |

Jenkins polls the repository and runs each branch and pull request through the managed pipeline.

## Developer Certificate of Origin

Every commit must include a `Signed-off-by` line. Use the `-s` flag:

```bash
git commit -s -m "Your commit message"
```

To sign off commits on an open pull request:

```bash
git rebase --signoff main
```

Read `CONTRIBUTING.md` for the full Developer Certificate of Origin text and contribution terms.

## Checklist

- [ ] Every commit has a DCO sign-off (`Signed-off-by:`).
- [ ] I agree to the contribution terms in `CONTRIBUTING.md`.
- [ ] I ran applicable validation commands and they passed.
- [ ] I updated user or operator docs when behavior or workflows changed.
- [ ] This pull request has no breaking change, or I documented it below.

### Dependencies and third-party code

Complete this section when you change a dependency or copy third-party code.

- [ ] The dependency license is allowed by `deny.toml`.
- [ ] I ran `make ci-check-deny`.
- [ ] I regenerated `THIRD_PARTY_NOTICES.md` with `bash ci/scripts/regenerate_third_party_notices.sh`.
- [ ] I ran `make ci-check-third-party`.
- [ ] I stated the source and license of copied files and kept original copyright notices.

### Breaking changes

<!-- Delete this section if there is no breaking change. -->

**Breaking change:**

**Migration steps for users:**
