# Flatpak packaging

The release pipeline builds a single-file Flatpak bundle for x86-64 Linux. The
bundle contains `verdictan`, `verdictan-update`, the license, and the third-party
notices. It is a GitHub release asset. Verdictan is not submitted to Flathub.

Install and run the bundle:

```bash
flatpak install --user ./verdictan-<version>-x86_64.flatpak
flatpak run com.verdictan.Verdictan --help
```

The bundle records Flathub as the source for the Freedesktop runtime only. The
Verdictan application itself comes from the downloaded bundle.

The Flatpak has network access and host filesystem access. These permissions
preserve the behavior of the gateway CLI, including local configuration files
and listening sockets.
