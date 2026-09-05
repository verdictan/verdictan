# Linux Package Repositories

The trusted release pipeline publishes the repository at
`https://verdictan.github.io/packages`.

The APT repository supports `amd64` Debian and Ubuntu systems. It uses the
`stable` suite and the `main` component.

The RPM repository supports `x86_64` CentOS, RHEL, Fedora, and Amazon Linux
2023 systems. It uses one distribution-neutral repository for compatible
systems.

`ci/scripts/build_linux_package_repositories.sh` performs these actions:

1. Verify the package name, version, and architecture.
2. Sign the RPM package with the repository OpenPGP key.
3. Generate and sign the APT release metadata.
4. Generate and sign the RPM repository metadata.
5. Export the public key and client repository files.
6. Reject a changed package for an indexed release version.
