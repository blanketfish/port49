---
title: port49
description: port49 lets you sign in to network devices with your SSO or a certificate instead of a shared TACACS+ password, with no changes to the devices.
---

# port49

port49 lets you sign in to network devices with your SSO or a certificate instead of a shared TACACS+
password — no changes to the devices.

## Why port49

- **Nothing to steal.** Each login uses a short-lived, single-use token minted for one device. There's
  no shared password sitting in every config backup.
- **Identity on devices that will never support it.** People and machines sign in with a certificate
  or through your identity provider; the device sees ordinary TACACS+.
- **Policy as reviewed code.** `port49 policy diff` fails a change that widens access until a
  [test](admin/policy.md#writing-tests) or a written acknowledgment accounts for it.
- **Built for a bad day.** Failure and break-glass behavior is measured in the lab, platform by
  platform; each [device page](admin/devices/index.md) says what was measured and what is still open.

## Where to start

- **How it fits together:** [Concepts](concepts/index.md).
- **Installing it:** [Install](operate/install/index.md) compares the three deployment shapes, which are
  peers: [systemd](operate/install/systemd.md), [containers](operate/install/container.md) and
  [Helm](operate/install/helm.md).
- **How a person signs in:** [Signing in](operate/login.md).
- **Who may do what:** [Policy](admin/policy.md).
- **Contributing:** [Contributing](contributing/index.md).

port49 is pre-release. The first beta will be `v0.1.0`; [Versions](operate/versions.md) says what beta
promises. The source is at <https://github.com/blanketfish/port49>, under Apache-2.0. This site is at
<https://blanketfish.github.io/port49/>.
