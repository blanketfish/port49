---
title: port49
description: port49 is a TACACS+ server that gives unmodified network devices certificate-based or OIDC-based identity.
---

# port49

port49 is a TACACS+ server that gives unmodified network devices certificate-based or OIDC-based
identity, with declarative policy.

## Why port49

- **Identity on devices that will never support it.** People and machines sign in with a certificate
  or through your identity provider; the device sees ordinary TACACS+.
- **Nothing to steal.** A device login uses a short-lived, single-use token minted for one device,
  not a shared password.
- **Policy as reviewed code.** `port49 policy diff` fails a change that widens access until a test or
  a written acknowledgment accounts for it.
- **Built for a bad day.** Failure behavior is measured per platform in the lab; the
  [qualified platforms](admin/devices/index.md#qualified-platforms) say which.
- **Runs where you run things.** [systemd](operate/install/systemd.md),
  [containers](operate/install/container.md) or [Helm](operate/install/helm.md), as peers.

## Where to start

- How it fits together: [Concepts](concepts/index.md).
- Installing it: [Install](operate/install/index.md).
- How a person signs in: [Signing in](operate/login.md).
- Contributing: [Contributing](contributing/index.md).

Beta: the first beta will be `v0.1.0`; see [Versions](operate/versions.md) for what beta promises.
The source is at <https://github.com/blanketfish/port49>, under Apache-2.0. This site is at
<https://blanketfish.github.io/port49/>.
