### Contribution terms

#### Sign off every commit

This project uses the Developer Certificate of Origin. It uses no Contributor
License Agreement.

Add a `Signed-off-by` line to every commit. Use the `-s` flag:

```bash
git commit -s -m "Your commit message"
```

The flag adds one line to the commit message:

```text
Signed-off-by: Jane Developer <jane@example.com>
```

Use your real name and a working email address. A pseudonym is not acceptable. A
continuous integration check refuses a pull request when any commit has no
sign-off.

To sign off the commits of an open pull request, run the command below and force
push the branch:

```bash
git rebase --signoff main
```

#### What the sign-off certifies

The sign-off certifies the Developer Certificate of Origin, version 1.1. The
full text follows. Nobody may change this text.

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same license (unless I am permitted to submit
    under a different license), as indicated in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Read paragraphs (a) and (b) together with the license terms below. This project
is source available and not open source. The Developer Certificate of Origin is
a fixed document, and this project publishes it without change.

#### License of your contribution: inbound equals outbound

Read `docs/license-faq.md` when you need guidance on permitted production use
before you contribute.

Read this section before you open a pull request.

1. **Inbound equals outbound.** You license your contribution under the same
   terms that this project publishes. Those terms are the Business Source
   License 1.1 with the parameters stated in the `LICENSE` file of this
   repository. Your contribution carries no additional term and no separate
   license.

2. **The Change License applies to your contribution.** The `LICENSE` file names
   a Change License and a Change Date. On the Change Date for a version, that
   version becomes available under the Change License. Your contribution
   converts with it. You grant the Licensor the right to publish, distribute,
   sublicense, and relicense your contribution under the Change License, on or
   after the Change Date.

3. **Later versions carry their own Change Date.** The Business Source License
   1.1 applies separately to each released version. You grant the same rights
   for each later version of this project that includes your contribution. Each
   version carries the Change Date that its own `LICENSE` file states.

4. **You keep your copyright.** You do not assign copyright to the Licensor. You
   grant a license. You may use your own contribution for any purpose.

5. **You grant a patent license.** You grant every recipient of the work a
   perpetual, worldwide, non-exclusive, royalty-free, irrevocable patent license
   to make, use, sell, offer for sale, import, and otherwise transfer your
   contribution. This license covers only the patent claims that you can license
   and that your contribution alone, or the combination of your contribution
   with the work, infringes.

6. **You confirm that you hold the rights.** You confirm that you own your
   contribution, or that you hold the rights to submit it under these terms. If
   your employer owns rights in your work, you confirm that your employer
   permits the contribution, or that your employer waived those rights.

7. **You give no warranty.** You supply your contribution without any warranty,
   to the extent that the law permits. The `LICENSE` file states the disclaimer
   that applies to the work.

8. **Your record stays public.** This repository is public. Your commits, your
   name, your email address, and your sign-off stay in the public history
   without a time limit.

If you cannot agree to these terms, do not open a pull request. Open an issue
instead, and describe the change in words.

#### Third-party code

Do not add third-party code that these terms do not permit.

Before you add a dependency or copy a file from another project, check the
license of that project. The dependency license policy of this repository lives
in `deny.toml`. A pull request that adds a license outside that allow list fails
the continuous integration check.

State the source and the license of any copied file in the pull request
description. Keep the original copyright notice in the file.
